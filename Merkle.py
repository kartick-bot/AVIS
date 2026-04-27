import hashlib
import struct
import bisect
import random
import statistics
import time
import math
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1


# ============================================================
# CONFIG
# Change LEAVES_PER_TREE for each separate script:
# 1024, 2048, 4096, 8192, 16384
# ============================================================

NUM_CHANNELS = 45000
LEAVES_PER_TREE = 1024
NUM_RUNS = 100
RNG_SEED = 42


# ============================================================
# HASH HELPERS
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160_fallback(data: bytes) -> bytes:
    return sha256(sha256(data))[:20]


# ============================================================
# SERIALIZATION HELPERS
# ============================================================

def encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def push_data(data: bytes) -> bytes:
    if len(data) < 0x4c:
        return bytes([len(data)]) + data
    if len(data) <= 0xff:
        return b"\x4c" + bytes([len(data)]) + data
    if len(data) <= 0xffff:
        return b"\x4d" + struct.pack("<H", len(data)) + data
    return b"\x4e" + struct.pack("<I", len(data)) + data


# ============================================================
# KEY HELPERS
# ============================================================

def generate_keypair() -> Tuple[SigningKey, VerifyingKey]:
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk


def compressed_pubkey(vk: VerifyingKey) -> bytes:
    point = vk.pubkey.point
    x = point.x()
    y = point.y()
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


# ============================================================
# SCRIPT HELPERS
# ============================================================

def p2pkh_scriptpubkey_from_vk(vk: VerifyingKey) -> bytes:
    h160 = hash160_fallback(compressed_pubkey(vk))
    return b"\x76\xa9" + push_data(h160) + b"\x88\xac"


def multisig_2of2_redeem_script(vk1: VerifyingKey, vk2: VerifyingKey) -> bytes:
    p1 = compressed_pubkey(vk1)
    p2 = compressed_pubkey(vk2)
    left, right = sorted([p1, p2])
    return b"\x52" + push_data(left) + push_data(right) + b"\x52\xae"


def p2sh_scriptpubkey_from_redeem_script(redeem_script: bytes) -> bytes:
    h160 = hash160_fallback(redeem_script)
    return b"\xa9" + push_data(h160) + b"\x87"


def fake_p2pkh_scriptsig(sig: bytes, vk: VerifyingKey) -> bytes:
    return push_data(sig) + push_data(compressed_pubkey(vk))


def fake_multisig_close_scriptsig(sig1: bytes, sig2: bytes, redeem_script: bytes) -> bytes:
    return b"\x00" + push_data(sig1) + push_data(sig2) + push_data(redeem_script)


# ============================================================
# TX DATA STRUCTURES
# ============================================================

@dataclass
class TxInput:
    prev_txid: bytes
    vout: int
    script_sig: bytes
    sequence: int

    def serialize(self) -> bytes:
        return (
            self.prev_txid[::-1]
            + struct.pack("<I", self.vout)
            + encode_varint(len(self.script_sig))
            + self.script_sig
            + struct.pack("<I", self.sequence)
        )


@dataclass
class TxOutput:
    value_sat: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return (
            struct.pack("<Q", self.value_sat)
            + encode_varint(len(self.script_pubkey))
            + self.script_pubkey
        )


@dataclass
class BitcoinStyleTransaction:
    version: int
    inputs: List[TxInput]
    outputs: List[TxOutput]
    locktime: int
    tx_type: str
    participant_pubkeys: Tuple[bytes, bytes] = field(default_factory=tuple)

    def serialize(self) -> bytes:
        return (
            struct.pack("<i", self.version)
            + encode_varint(len(self.inputs))
            + b"".join(txin.serialize() for txin in self.inputs)
            + encode_varint(len(self.outputs))
            + b"".join(txout.serialize() for txout in self.outputs)
            + struct.pack("<I", self.locktime)
        )

    def txid_bytes(self) -> bytes:
        return hash256(self.serialize())

    def sighash_message(self) -> bytes:
        return hash256(self.serialize())


# ============================================================
# SIGNATURE HELPERS
# ============================================================

def der_encode_int(x: int) -> bytes:
    xb = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if xb[0] & 0x80:
        xb = b"\x00" + xb
    return b"\x02" + bytes([len(xb)]) + xb


def der_encode_sig(r: int, s: int) -> bytes:
    rb = der_encode_int(r)
    sb = der_encode_int(s)
    seq = rb + sb
    return b"\x30" + bytes([len(seq)]) + seq


def sign_digest(sk: SigningKey, msg: bytes) -> bytes:
    return sk.sign_digest_deterministic(
        msg,
        hashfunc=hashlib.sha256,
        sigencode=lambda r, s, order: der_encode_sig(r, s),
    )


# ============================================================
# BTC-STYLE TRANSACTIONS
# ============================================================

def fake_prev_txid(tag: str, idx: int) -> bytes:
    return hash256(f"{tag}-{idx}".encode())


def create_opening_transaction(
    funder_sk: SigningKey,
    funder_vk: VerifyingKey,
    counterparty_vk: VerifyingKey,
    prev_txid: bytes,
    prev_vout: int,
    utxo_value_sat: int,
    channel_value_sat: int,
    fee_sat: int,
    sequence: int = 0xFFFFFFFF,
) -> BitcoinStyleTransaction:
    redeem_script = multisig_2of2_redeem_script(funder_vk, counterparty_vk)
    funding_spk = p2sh_scriptpubkey_from_redeem_script(redeem_script)
    change_spk = p2pkh_scriptpubkey_from_vk(funder_vk)

    change_sat = utxo_value_sat - channel_value_sat - fee_sat
    if change_sat < 0:
        raise ValueError("Insufficient UTXO value")

    tx = BitcoinStyleTransaction(
        version=2,
        inputs=[TxInput(prev_txid, prev_vout, b"", sequence)],
        outputs=[
            TxOutput(channel_value_sat, funding_spk),
            TxOutput(change_sat, change_spk),
        ],
        locktime=0,
        tx_type="open",
        participant_pubkeys=(compressed_pubkey(funder_vk), compressed_pubkey(counterparty_vk)),
    )

    sig = sign_digest(funder_sk, tx.sighash_message()) + b"\x01"
    tx.inputs[0].script_sig = fake_p2pkh_scriptsig(sig, funder_vk)
    return tx


def create_closing_transaction(
    open_tx: BitcoinStyleTransaction,
    vk1: VerifyingKey,
    sk1: SigningKey,
    vk2: VerifyingKey,
    sk2: SigningKey,
    payout1_sat: int,
    payout2_sat: int,
    fee_sat: int,
    sequence: int = 0xFFFFFFFF,
) -> BitcoinStyleTransaction:
    funding_value = open_tx.outputs[0].value_sat
    if payout1_sat + payout2_sat + fee_sat != funding_value:
        raise ValueError("Closing outputs + fee must equal funding output")

    redeem_script = multisig_2of2_redeem_script(vk1, vk2)

    tx = BitcoinStyleTransaction(
        version=2,
        inputs=[TxInput(open_tx.txid_bytes()[::-1], 0, b"", sequence)],
        outputs=[
            TxOutput(payout1_sat, p2pkh_scriptpubkey_from_vk(vk1)),
            TxOutput(payout2_sat, p2pkh_scriptpubkey_from_vk(vk2)),
        ],
        locktime=0,
        tx_type="close",
        participant_pubkeys=(compressed_pubkey(vk1), compressed_pubkey(vk2)),
    )

    msg = tx.sighash_message()
    sig1 = sign_digest(sk1, msg) + b"\x01"
    sig2 = sign_digest(sk2, msg) + b"\x01"
    tx.inputs[0].script_sig = fake_multisig_close_scriptsig(sig1, sig2, redeem_script)
    return tx


def compute_digest_from_pubkeys(pk1: bytes, pk2: bytes, flag: bytes) -> bytes:
    left, right = sorted([pk1, pk2])
    return flag + sha256(left + right)


def sample_btc_style_channels(num_channels: int) -> Tuple[List[Dict[str, Any]], List[BitcoinStyleTransaction], List[BitcoinStyleTransaction]]:
    channels = []
    opening_txs = []
    closing_txs = []

    for i in range(num_channels):
        sk1, vk1 = generate_keypair()
        sk2, vk2 = generate_keypair()

        open_tx = create_opening_transaction(
            funder_sk=sk1,
            funder_vk=vk1,
            counterparty_vk=vk2,
            prev_txid=fake_prev_txid("funding-utxo", i),
            prev_vout=0,
            utxo_value_sat=1_500_000,
            channel_value_sat=1_200_000,
            fee_sat=2_000,
        )

        close_tx = create_closing_transaction(
            open_tx=open_tx,
            vk1=vk1,
            sk1=sk1,
            vk2=vk2,
            sk2=sk2,
            payout1_sat=600_000,
            payout2_sat=598_500,
            fee_sat=1_500,
        )

        pk1 = compressed_pubkey(vk1)
        pk2 = compressed_pubkey(vk2)

        channels.append({
            "channel_id": i,
            "vk1": pk1,
            "vk2": pk2,
            "open_digest": compute_digest_from_pubkeys(pk1, pk2, b"O"),
            "close_digest": compute_digest_from_pubkeys(pk1, pk2, b"C"),
            "open_tree_index": None,
            "open_leaf_index": None,
            "close_tree_index": None,
            "close_leaf_index": None,
            "close_inserted": False,
        })

        opening_txs.append(open_tx)
        closing_txs.append(close_tx)

    return channels, opening_txs, closing_txs


# ============================================================
# MERKLE TREE
# ============================================================

def merkle_parent(left: bytes, right: bytes) -> bytes:
    return sha256(left + right)


def build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    if not leaves:
        raise ValueError("Merkle tree must have at least one leaf")

    tree = [leaves[:]]
    current = leaves[:]

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])

        nxt = []
        for i in range(0, len(current), 2):
            nxt.append(merkle_parent(current[i], current[i + 1]))
        tree.append(nxt)
        current = nxt

    return tree


def get_merkle_root(tree: List[List[bytes]]) -> bytes:
    return tree[-1][0]


class SortedMerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.original_leaves = leaves[:]
        self.leaves = sorted(leaves)
        self.tree = build_merkle_tree(self.leaves)
        self.root = get_merkle_root(self.tree)
        self.leaf_to_index = {leaf: idx for idx, leaf in enumerate(self.leaves)}

    def get_proof(self, idx: int) -> List[Tuple[bytes, str]]:
        proof = []
        index = idx

        for level in self.tree[:-1]:
            if index % 2 == 0:
                sibling = index + 1 if index + 1 < len(level) else index
                proof.append((level[sibling], "right"))
            else:
                sibling = index - 1
                proof.append((level[sibling], "left"))
            index //= 2

        return proof

    def membership_proof_by_index(self, idx: int) -> Dict[str, Any]:
        leaf = self.leaves[idx]
        return {
            "leaf": leaf,
            "index": idx,
            "proof": self.get_proof(idx),
            "root": self.root,
        }

    def non_membership_indices(self, query: bytes) -> Dict[str, Any]:
        """
        Finds predecessor/successor indexes OUTSIDE timing.
        This is lookup/preprocessing, not proof computation.
        """
        pos = bisect.bisect_left(self.leaves, query)

        if pos < len(self.leaves) and self.leaves[pos] == query:
            raise ValueError("Query exists, so non-membership proof is invalid")

        if pos == 0:
            return {
                "dne_case": "before_first_leaf",
                "query": query,
                "successor_index": 0,
                "root": self.root,
            }

        if pos == len(self.leaves):
            return {
                "dne_case": "after_last_leaf",
                "query": query,
                "predecessor_index": len(self.leaves) - 1,
                "root": self.root,
            }

        return {
            "dne_case": "between",
            "query": query,
            "predecessor_index": pos - 1,
            "successor_index": pos,
            "root": self.root,
        }

    def non_membership_proof_from_indices(self, idx_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Proof computation/extraction only.
        No bisect here.
        """
        q = idx_info["query"]
        case = idx_info["dne_case"]

        if case == "before_first_leaf":
            succ_idx = idx_info["successor_index"]
            succ = self.leaves[succ_idx]
            return {
                "dne_case": case,
                "query": q,
                "successor": succ,
                "successor_membership_proof": self.membership_proof_by_index(succ_idx),
                "root": self.root,
            }

        if case == "after_last_leaf":
            pred_idx = idx_info["predecessor_index"]
            pred = self.leaves[pred_idx]
            return {
                "dne_case": case,
                "query": q,
                "predecessor": pred,
                "predecessor_membership_proof": self.membership_proof_by_index(pred_idx),
                "root": self.root,
            }

        pred_idx = idx_info["predecessor_index"]
        succ_idx = idx_info["successor_index"]
        pred = self.leaves[pred_idx]
        succ = self.leaves[succ_idx]

        return {
            "dne_case": case,
            "query": q,
            "predecessor": pred,
            "successor": succ,
            "predecessor_membership_proof": self.membership_proof_by_index(pred_idx),
            "successor_membership_proof": self.membership_proof_by_index(succ_idx),
            "root": self.root,
        }


# ============================================================
# VERIFIERS
# ============================================================

def verify_membership_proof(proof_obj: Dict[str, Any]) -> bool:
    current = proof_obj["leaf"]

    for sibling, pos in proof_obj["proof"]:
        if pos == "right":
            current = sha256(current + sibling)
        elif pos == "left":
            current = sha256(sibling + current)
        else:
            return False

    return current == proof_obj["root"]


def verify_non_membership_proof(proof_obj: Dict[str, Any]) -> bool:
    q = proof_obj["query"]
    root = proof_obj["root"]
    case = proof_obj["dne_case"]

    if case == "before_first_leaf":
        succ = proof_obj["successor"]
        succ_ok = verify_membership_proof(proof_obj["successor_membership_proof"])
        return succ_ok and q < succ and proof_obj["successor_membership_proof"]["root"] == root

    if case == "after_last_leaf":
        pred = proof_obj["predecessor"]
        pred_ok = verify_membership_proof(proof_obj["predecessor_membership_proof"])
        return pred_ok and pred < q and proof_obj["predecessor_membership_proof"]["root"] == root

    pred = proof_obj["predecessor"]
    succ = proof_obj["successor"]

    pred_ok = verify_membership_proof(proof_obj["predecessor_membership_proof"])
    succ_ok = verify_membership_proof(proof_obj["successor_membership_proof"])

    return (
        pred_ok
        and succ_ok
        and pred < q < succ
        and proof_obj["predecessor_membership_proof"]["root"] == root
        and proof_obj["successor_membership_proof"]["root"] == root
    )


# ============================================================
# CHECKPOINTS
# ============================================================

def build_checkpoint_proof(smts: List[SortedMerkleTree], start_index: int) -> List[Dict[str, Any]]:
    proof = []

    for i in range(start_index, len(smts) - 1):
        current_root = smts[i].root
        next_tree = smts[i + 1]
        next_idx = next_tree.leaf_to_index[current_root]

        proof.append({
            "from_tree_index": i,
            "to_tree_index": i + 1,
            "current_root": current_root,
            "membership_proof_in_next_tree": next_tree.membership_proof_by_index(next_idx),
            "next_root": next_tree.root,
        })

    return proof


def extract_checkpoint_paths_only(smts: List[SortedMerkleTree], start_index: int) -> List[List[Tuple[bytes, str]]]:
    """
    Proof extraction timing helper for checkpoint proofs.
    It retrieves only sibling paths for root_i in tree i+1.
    It does not build full checkpoint proof dictionaries.
    """
    paths = []

    for i in range(start_index, len(smts) - 1):
        current_root = smts[i].root
        next_tree = smts[i + 1]
        next_idx = next_tree.leaf_to_index[current_root]
        paths.append(next_tree.get_proof(next_idx))

    return paths


def verify_checkpoint_proof(checkpoint_proof: List[Dict[str, Any]], final_checkpoint_root: bytes) -> bool:
    if not checkpoint_proof:
        return True

    for i, step in enumerate(checkpoint_proof):
        mp = step["membership_proof_in_next_tree"]

        if mp["leaf"] != step["current_root"]:
            return False
        if mp["root"] != step["next_root"]:
            return False
        if not verify_membership_proof(mp):
            return False

        if i < len(checkpoint_proof) - 1:
            if step["next_root"] != checkpoint_proof[i + 1]["current_root"]:
                return False
        else:
            if step["next_root"] != final_checkpoint_root:
                return False

    return True


# ============================================================
# CONTROLLED FOREST CONSTRUCTION
# ============================================================

def checkpoint_forest_from_tree_payloads(
    tree_payloads: List[List[bytes]],
    leaves_per_tree: int
) -> Tuple[List[SortedMerkleTree], bytes]:
    smts = []
    prev_root = None

    for tree_idx, payload in enumerate(tree_payloads):
        if tree_idx == 0:
            chunk = payload[:]
        else:
            chunk = [prev_root] + payload[:]

        if len(chunk) > leaves_per_tree:
            raise ValueError(
                f"Tree {tree_idx} has {len(chunk)} leaves, max allowed is {leaves_per_tree}"
            )

        smt = SortedMerkleTree(chunk)
        smts.append(smt)
        prev_root = smt.root

    return smts, smts[-1].root


def populate_digest_locations(smts: List[SortedMerkleTree], channels: List[Dict[str, Any]]) -> None:
    digest_to_location: Dict[bytes, Tuple[int, int]] = {}

    for tree_idx, smt in enumerate(smts):
        for leaf, leaf_idx in smt.leaf_to_index.items():
            digest_to_location[leaf] = (tree_idx, leaf_idx)

    for ch in channels:
        open_loc = digest_to_location.get(ch["open_digest"])
        if open_loc is not None:
            ch["open_tree_index"], ch["open_leaf_index"] = open_loc

        close_loc = digest_to_location.get(ch["close_digest"])
        if close_loc is not None:
            ch["close_tree_index"], ch["close_leaf_index"] = close_loc
            ch["close_inserted"] = True


def build_controlled_forest(
    channels: List[Dict[str, Any]],
    leaves_per_tree: int
) -> Tuple[List[SortedMerkleTree], bytes, int, int]:
    """
    Rules:
    - opening in tree i, closing in tree j where j > i
    - open-open: opening in first tree, closing absent
    - open-close: opening in first tree, closing in last tree
    """

    open_open_channel_id = 0
    open_close_channel_id = 1

    payload_cap = leaves_per_tree - 1

    open_region_trees = math.ceil((len(channels) + 5) / payload_cap) + 2
    close_region_trees = math.ceil((len(channels) + 5) / payload_cap) + 2

    num_trees = open_region_trees + close_region_trees

    tree_payloads: List[List[bytes]] = [[] for _ in range(num_trees)]
    payload_capacity = [leaves_per_tree] + [leaves_per_tree - 1] * (num_trees - 1)

    def insert_payload(tree_idx: int, digest: bytes) -> None:
        if len(tree_payloads[tree_idx]) >= payload_capacity[tree_idx]:
            raise RuntimeError(f"Tree {tree_idx} is full")
        tree_payloads[tree_idx].append(digest)

    def insert_sequential(start_tree: int, end_tree_exclusive: int, digest: bytes, pointer: List[int]) -> int:
        while pointer[0] < end_tree_exclusive:
            t = pointer[0]
            if len(tree_payloads[t]) < payload_capacity[t]:
                tree_payloads[t].append(digest)
                return t
            pointer[0] += 1
        raise RuntimeError("No capacity left in requested tree range")

    # open-open channel: opening in first tree, closing absent
    insert_payload(0, channels[open_open_channel_id]["open_digest"])

    # open-close channel: opening in first tree, closing in last tree
    insert_payload(0, channels[open_close_channel_id]["open_digest"])
    insert_payload(num_trees - 1, channels[open_close_channel_id]["close_digest"])

    # all other channels: opening early, closing later
    open_ptr = [0]
    close_ptr = [open_region_trees]

    for ch in channels[2:]:
        insert_sequential(0, open_region_trees, ch["open_digest"], open_ptr)
        insert_sequential(open_region_trees, num_trees, ch["close_digest"], close_ptr)

    smts, checkpoint_root = checkpoint_forest_from_tree_payloads(tree_payloads, leaves_per_tree)
    populate_digest_locations(smts, channels)

    assert channels[open_open_channel_id]["open_tree_index"] == 0
    assert channels[open_open_channel_id]["close_inserted"] is False

    assert channels[open_close_channel_id]["open_tree_index"] == 0
    assert channels[open_close_channel_id]["close_tree_index"] == len(smts) - 1

    return smts, checkpoint_root, open_open_channel_id, open_close_channel_id


# ============================================================
# DNE QUERY CONSTRUCTION
# ============================================================

def make_query_before_first(tree: SortedMerkleTree) -> bytes:
    return b"\x00" * len(tree.leaves[0])


def make_query_after_last(tree: SortedMerkleTree) -> bytes:
    return b"\xff" * len(tree.leaves[-1])


def make_query_between(a: bytes, b: bytes) -> Optional[bytes]:
    ai = int.from_bytes(a, "big")
    bi = int.from_bytes(b, "big")

    if not ai < bi:
        return None
    if bi - ai <= 1:
        return None

    mid = ai + (bi - ai) // 2
    max_val = (1 << (8 * len(a))) - 1

    if mid < 0 or mid > max_val:
        return None

    q = mid.to_bytes(len(a), "big")
    if a < q < b:
        return q

    return None


def choose_random_dne_query_for_tree(smt: SortedMerkleTree, rng: random.Random) -> bytes:
    choices = [
        make_query_before_first(smt),
        make_query_after_last(smt),
    ]

    for pos in range(1, len(smt.leaves)):
        q = make_query_between(smt.leaves[pos - 1], smt.leaves[pos])
        if q is not None:
            choices.append(q)

    return rng.choice(choices)


# ============================================================
# TIMING HELPERS
# ============================================================

def ms(x: float) -> float:
    return x * 1000.0


def print_run_metric(run_id: int, name: str, value: float) -> None:
    print(f"Run {run_id:02d} | {name}: {ms(value):.6f} ms")


def print_summary_metric(name: str, values: List[float]) -> None:
    mean = statistics.mean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    print(f"{name}: mean={ms(mean):.6f} ms std={ms(std):.6f} ms")


# ============================================================
# BENCHMARK
# ============================================================

def run_benchmark() -> None:
    digest_times = []
    tree_times = []
    checkpoint_times = []

    open_open_individual_compute = []
    open_open_checkpoint_compute = []
    open_open_individual_verify = []
    open_open_checkpoint_verify = []

    open_close_individual_compute = []
    open_close_checkpoint_compute = []
    open_close_individual_verify = []
    open_close_checkpoint_verify = []

    dne_individual_compute = []
    dne_checkpoint_compute = []
    dne_individual_verify = []
    dne_checkpoint_verify = []

    print(f"channels={NUM_CHANNELS}, leaves_per_tree={LEAVES_PER_TREE}, runs={NUM_RUNS}")
    print("=" * 90)

    for run_id in range(1, NUM_RUNS + 1):
        rng = random.Random(RNG_SEED + run_id)

        print(f"\nRUN {run_id}")
        print("-" * 90)

        channels, opening_txs, closing_txs = sample_btc_style_channels(NUM_CHANNELS)

        t0 = time.perf_counter()
        _ = [ch["open_digest"] for ch in channels]
        _ = [ch["close_digest"] for ch in channels]
        t1 = time.perf_counter()
        digest_times.append(t1 - t0)
        print_run_metric(run_id, "digest creation", t1 - t0)

        t0 = time.perf_counter()
        smts, checkpoint_root, open_open_channel_id, open_close_channel_id = build_controlled_forest(
            channels,
            LEAVES_PER_TREE,
        )
        t1 = time.perf_counter()
        tree_times.append(t1 - t0)
        print_run_metric(run_id, "tree construction", t1 - t0)
        print(f"Run {run_id:02d} | number of trees: {len(smts)}")

        t0 = time.perf_counter()
        _all_checkpoint_paths = [build_checkpoint_proof(smts, i) for i in range(len(smts))]
        t1 = time.perf_counter()
        checkpoint_times.append(t1 - t0)
        print_run_metric(run_id, "checkpoint construction", t1 - t0)

        # ====================================================
        # OPEN -> OPEN
        # ====================================================
        oo_channel = channels[open_open_channel_id]
        oo_open_tree = oo_channel["open_tree_index"]
        oo_open_leaf_idx = oo_channel["open_leaf_index"]
        oo_close_digest = oo_channel["close_digest"]

        assert oo_open_tree == 0
        assert oo_channel["close_inserted"] is False

        # lookup/preprocessing outside timing
        oo_close_idx_infos = [
            smts[i].non_membership_indices(oo_close_digest)
            for i in range(oo_open_tree, len(smts))
        ]

        # proof computation = sibling-path extraction only
        # Do not build full proof dictionaries inside this timer.
        t0 = time.perf_counter()
        oo_open_path = smts[oo_open_tree].get_proof(oo_open_leaf_idx)

        oo_close_paths = []
        for i, info in zip(range(oo_open_tree, len(smts)), oo_close_idx_infos):
            if "predecessor_index" in info:
                oo_close_paths.append(smts[i].get_proof(info["predecessor_index"]))
            if "successor_index" in info:
                oo_close_paths.append(smts[i].get_proof(info["successor_index"]))
        t1 = time.perf_counter()
        open_open_individual_compute.append(t1 - t0)
        print_run_metric(run_id, "open-open proof extraction", t1 - t0)

        # Build complete proof objects AFTER timing so verification can use them.
        oo_open_membership = smts[oo_open_tree].membership_proof_by_index(oo_open_leaf_idx)
        oo_close_nonmembership = [
            smts[i].non_membership_proof_from_indices(info)
            for i, info in zip(range(oo_open_tree, len(smts)), oo_close_idx_infos)
        ]

        # checkpoint proof computation = checkpoint sibling-path extraction only
        t0 = time.perf_counter()
        oo_open_checkpoint_paths = extract_checkpoint_paths_only(smts, oo_open_tree)
        oo_close_checkpoint_paths = [
            extract_checkpoint_paths_only(smts, i)
            for i in range(oo_open_tree, len(smts))
        ]
        t1 = time.perf_counter()
        open_open_checkpoint_compute.append(t1 - t0)
        print_run_metric(run_id, "open-open checkpoint proof extraction", t1 - t0)

        # Build complete checkpoint proof objects AFTER timing.
        oo_open_checkpoint = build_checkpoint_proof(smts, oo_open_tree)
        oo_close_checkpoints = [
            build_checkpoint_proof(smts, i)
            for i in range(oo_open_tree, len(smts))
        ]

        t0 = time.perf_counter()
        oo_individual_ok = verify_membership_proof(oo_open_membership) and all(
            verify_non_membership_proof(p) for p in oo_close_nonmembership
        )
        t1 = time.perf_counter()
        open_open_individual_verify.append(t1 - t0)
        print_run_metric(run_id, "open-open proof verification", t1 - t0)

        t0 = time.perf_counter()
        oo_checkpoint_ok = verify_checkpoint_proof(oo_open_checkpoint, checkpoint_root) and all(
            verify_checkpoint_proof(cp, checkpoint_root)
            for cp in oo_close_checkpoints
        )
        t1 = time.perf_counter()
        open_open_checkpoint_verify.append(t1 - t0)
        print_run_metric(run_id, "open-open checkpoint verification", t1 - t0)

        # ====================================================
        # OPEN -> CLOSE
        # ====================================================
        oc_channel = channels[open_close_channel_id]
        oc_open_tree = oc_channel["open_tree_index"]
        oc_open_leaf_idx = oc_channel["open_leaf_index"]
        oc_close_tree = oc_channel["close_tree_index"]
        oc_close_leaf_idx = oc_channel["close_leaf_index"]

        assert oc_open_tree == 0
        assert oc_close_tree == len(smts) - 1

        # proof computation = sibling-path extraction only
        t0 = time.perf_counter()
        oc_open_path = smts[oc_open_tree].get_proof(oc_open_leaf_idx)
        oc_close_path = smts[oc_close_tree].get_proof(oc_close_leaf_idx)
        t1 = time.perf_counter()
        open_close_individual_compute.append(t1 - t0)
        print_run_metric(run_id, "open-close proof extraction", t1 - t0)

        # Build complete proof objects AFTER timing so verification can use them.
        oc_open_membership = smts[oc_open_tree].membership_proof_by_index(oc_open_leaf_idx)
        oc_close_membership = smts[oc_close_tree].membership_proof_by_index(oc_close_leaf_idx)

        # checkpoint proof computation = checkpoint sibling-path extraction only
        t0 = time.perf_counter()
        oc_open_checkpoint_paths = extract_checkpoint_paths_only(smts, oc_open_tree)
        oc_close_checkpoint_paths = extract_checkpoint_paths_only(smts, oc_close_tree)
        t1 = time.perf_counter()
        open_close_checkpoint_compute.append(t1 - t0)
        print_run_metric(run_id, "open-close checkpoint proof extraction", t1 - t0)

        # Build complete checkpoint proof objects AFTER timing.
        oc_open_checkpoint = build_checkpoint_proof(smts, oc_open_tree)
        oc_close_checkpoint = build_checkpoint_proof(smts, oc_close_tree)

        t0 = time.perf_counter()
        oc_individual_ok = (
            verify_membership_proof(oc_open_membership)
            and verify_membership_proof(oc_close_membership)
        )
        t1 = time.perf_counter()
        open_close_individual_verify.append(t1 - t0)
        print_run_metric(run_id, "open-close proof verification", t1 - t0)

        t0 = time.perf_counter()
        oc_checkpoint_ok = (
            verify_checkpoint_proof(oc_open_checkpoint, checkpoint_root)
            and verify_checkpoint_proof(oc_close_checkpoint, checkpoint_root)
        )
        t1 = time.perf_counter()
        open_close_checkpoint_verify.append(t1 - t0)
        print_run_metric(run_id, "open-close checkpoint verification", t1 - t0)

        # ====================================================
        # DNE
        # ====================================================
        dne_tree_idx = rng.randrange(len(smts))
        dne_query = choose_random_dne_query_for_tree(smts[dne_tree_idx], rng)

        # lookup/preprocessing outside timing
        dne_idx_info = smts[dne_tree_idx].non_membership_indices(dne_query)

        # proof computation = sibling-path extraction only
        t0 = time.perf_counter()
        dne_paths = []
        if "predecessor_index" in dne_idx_info:
            dne_paths.append(smts[dne_tree_idx].get_proof(dne_idx_info["predecessor_index"]))
        if "successor_index" in dne_idx_info:
            dne_paths.append(smts[dne_tree_idx].get_proof(dne_idx_info["successor_index"]))
        t1 = time.perf_counter()
        dne_individual_compute.append(t1 - t0)
        print_run_metric(run_id, "dne proof extraction", t1 - t0)

        # Build complete proof object AFTER timing so verification can use it.
        dne_nonmembership = smts[dne_tree_idx].non_membership_proof_from_indices(dne_idx_info)

        # checkpoint proof computation = checkpoint sibling-path extraction only
        t0 = time.perf_counter()
        dne_checkpoint_paths = extract_checkpoint_paths_only(smts, dne_tree_idx)
        t1 = time.perf_counter()
        dne_checkpoint_compute.append(t1 - t0)
        print_run_metric(run_id, "dne checkpoint proof extraction", t1 - t0)

        # Build complete checkpoint proof object AFTER timing.
        dne_checkpoint = build_checkpoint_proof(smts, dne_tree_idx)

        t0 = time.perf_counter()
        dne_individual_ok = verify_non_membership_proof(dne_nonmembership)
        t1 = time.perf_counter()
        dne_individual_verify.append(t1 - t0)
        print_run_metric(run_id, "dne proof verification", t1 - t0)

        t0 = time.perf_counter()
        dne_checkpoint_ok = verify_checkpoint_proof(dne_checkpoint, checkpoint_root)
        t1 = time.perf_counter()
        dne_checkpoint_verify.append(t1 - t0)
        print_run_metric(run_id, "dne checkpoint verification", t1 - t0)

        assert oo_individual_ok and oo_checkpoint_ok
        assert oc_individual_ok and oc_checkpoint_ok
        assert dne_individual_ok and dne_checkpoint_ok

    print("\n" + "=" * 90)
    print("FINAL AVERAGE AND STANDARD DEVIATION")
    print("=" * 90)

    print_summary_metric("digest creation", digest_times)
    print_summary_metric("tree construction", tree_times)
    print_summary_metric("checkpoint construction", checkpoint_times)

    print()
    print_summary_metric("open-open proof extraction", open_open_individual_compute)
    print_summary_metric("open-open checkpoint proof extraction", open_open_checkpoint_compute)
    print_summary_metric("open-open proof verification", open_open_individual_verify)
    print_summary_metric("open-open checkpoint verification", open_open_checkpoint_verify)

    print()
    print_summary_metric("open-close proof extraction", open_close_individual_compute)
    print_summary_metric("open-close checkpoint proof extraction", open_close_checkpoint_compute)
    print_summary_metric("open-close proof verification", open_close_individual_verify)
    print_summary_metric("open-close checkpoint verification", open_close_checkpoint_verify)

    print()
    print_summary_metric("dne proof extraction", dne_individual_compute)
    print_summary_metric("dne checkpoint proof extraction", dne_checkpoint_compute)
    print_summary_metric("dne proof verification", dne_individual_verify)
    print_summary_metric("dne checkpoint verification", dne_checkpoint_verify)


if __name__ == "__main__":
    run_benchmark()
