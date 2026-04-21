import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1


# ============================================================
# CONFIG
# ============================================================

NUM_OPEN = 500
NUM_CLOSE = 500
LEAVES_PER_TREE = 128
OUTPUT_JSON = "btc_channel_merkle_output_with_dne.json"


# ============================================================
# HASH HELPERS
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    # portable fallback for environments without RIPEMD160
    return sha256(sha256(data))[:20]


# ============================================================
# BITCOIN SERIALIZATION HELPERS
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

def generate_keypair() -> Tuple[SigningKey, Any]:
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk


def compressed_pubkey(vk) -> bytes:
    point = vk.pubkey.point
    x = point.x()
    y = point.y()
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


# ============================================================
# SCRIPT HELPERS
# ============================================================

def p2pkh_scriptpubkey_from_vk(vk) -> bytes:
    return b"\x76\xa9" + push_data(hash160(compressed_pubkey(vk))) + b"\x88\xac"


def multisig_2of2_redeem_script(vk1, vk2) -> bytes:
    p1 = compressed_pubkey(vk1)
    p2 = compressed_pubkey(vk2)
    left, right = sorted([p1, p2])
    return b"\x52" + push_data(left) + push_data(right) + b"\x52\xae"


def p2sh_scriptpubkey_from_redeem_script(redeem_script: bytes) -> bytes:
    return b"\xa9" + push_data(hash160(redeem_script)) + b"\x87"


def fake_p2pkh_scriptsig(sig: bytes, vk) -> bytes:
    return push_data(sig) + push_data(compressed_pubkey(vk))


def fake_multisig_close_scriptsig(sig1: bytes, sig2: bytes, redeem_script: bytes) -> bytes:
    return b"\x00" + push_data(sig1) + push_data(sig2) + push_data(redeem_script)


# ============================================================
# TRANSACTION STRUCTURES
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

    def to_json(self) -> Dict[str, Any]:
        return {
            "prev_txid": self.prev_txid.hex(),
            "vout": self.vout,
            "scriptSig": self.script_sig.hex(),
            "sequence": self.sequence,
        }


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

    def to_json(self) -> Dict[str, Any]:
        return {
            "value_sat": self.value_sat,
            "scriptPubKey": self.script_pubkey.hex(),
        }


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
            + b"".join(i.serialize() for i in self.inputs)
            + encode_varint(len(self.outputs))
            + b"".join(o.serialize() for o in self.outputs)
            + struct.pack("<I", self.locktime)
        )

    def txid_bytes(self) -> bytes:
        return hash256(self.serialize())

    def txid_hex(self) -> str:
        return self.txid_bytes()[::-1].hex()

    def sighash_message(self) -> bytes:
        return hash256(self.serialize())

    def to_json(self) -> Dict[str, Any]:
        return {
            "txid": self.txid_hex(),
            "version": self.version,
            "inputs": [i.to_json() for i in self.inputs],
            "outputs": [o.to_json() for o in self.outputs],
            "locktime": self.locktime,
            "tx_type": self.tx_type,
            "participant_pubkeys": [pk.hex() for pk in self.participant_pubkeys],
            "raw_tx_hex": self.serialize().hex(),
        }


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
# BTC-STYLE CHANNEL TRANSACTIONS
# ============================================================

def create_opening_transaction(
    funder_sk: SigningKey,
    funder_vk,
    counterparty_vk,
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
    vk1,
    sk1: SigningKey,
    vk2,
    sk2: SigningKey,
    payout1_sat: int,
    payout2_sat: int,
    fee_sat: int,
    sequence: int = 0xFFFFFFFF,
) -> BitcoinStyleTransaction:
    funding_value = open_tx.outputs[0].value_sat
    if payout1_sat + payout2_sat + fee_sat != funding_value:
        raise ValueError("Close outputs + fee must equal funding output")

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


# ============================================================
# DIGESTS
# ============================================================

def compute_digest_from_transaction(tx: BitcoinStyleTransaction, flag: bytes) -> bytes:
    pk1, pk2 = tx.participant_pubkeys
    left, right = sorted([pk1, pk2])
    return flag + sha256(left + right)


def flip_flag(digest: bytes) -> bytes:
    return (b"C" if digest[:1] == b"O" else b"O") + digest[1:]


# ============================================================
# MERKLE TREE
# ============================================================

def merkle_parent(left: bytes, right: bytes) -> bytes:
    return sha256(left + right)


def build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    if not leaves:
        raise ValueError("must have at least one leaf")

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


def level_and_offset(index: int, tree_height_from_leaves: int) -> Tuple[int, int]:
    return tree_height_from_leaves, index


class SortedMerkleTree:
    def __init__(self, leaves: List[bytes]):
        self.original_leaves = leaves[:]
        self.leaves = sorted(leaves)
        self.tree = build_merkle_tree(self.leaves)
        self.root = get_merkle_root(self.tree)

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

    def membership_proof(self, leaf: bytes) -> Dict[str, Any]:
        idx = self.leaves.index(leaf)
        return {
            "leaf": leaf.hex(),
            "index": idx,
            "proof": [(sib.hex(), pos) for sib, pos in self.get_proof(idx)],
            "root": self.root.hex(),
        }

    def classify_between_case(self, pos: int) -> str:
        n = len(self.leaves)
        if pos <= 0 or pos >= n:
            raise ValueError("between-case classification requires 0 < pos < len(leaves)")

        left_idx = pos - 1
        right_idx = pos

        if left_idx // 2 == right_idx // 2:
            return "between_leaves_same_subtree"

        if left_idx // 2 != right_idx // 2 and left_idx // 4 == right_idx // 4:
            return "between_two_subtrees_same_parent"

        return "between_general"

    def non_membership_proof(self, query: bytes) -> Dict[str, Any]:
        import bisect

        pos = bisect.bisect_left(self.leaves, query)

        if pos < len(self.leaves) and self.leaves[pos] == query:
            raise ValueError("query exists; DNE proof invalid")

        if pos == 0:
            succ = self.leaves[0]
            return {
                "dne_case": "before_first_leaf",
                "query": query.hex(),
                "successor": succ.hex(),
                "successor_index": 0,
                "successor_membership_proof": self.membership_proof(succ),
                "root": self.root.hex(),
            }

        if pos == len(self.leaves):
            pred = self.leaves[-1]
            pred_idx = len(self.leaves) - 1
            return {
                "dne_case": "after_last_leaf",
                "query": query.hex(),
                "predecessor": pred.hex(),
                "predecessor_index": pred_idx,
                "predecessor_membership_proof": self.membership_proof(pred),
                "root": self.root.hex(),
            }

        pred = self.leaves[pos - 1]
        succ = self.leaves[pos]

        return {
            "dne_case": self.classify_between_case(pos),
            "query": query.hex(),
            "predecessor": pred.hex(),
            "predecessor_index": pos - 1,
            "predecessor_membership_proof": self.membership_proof(pred),
            "successor": succ.hex(),
            "successor_index": pos,
            "successor_membership_proof": self.membership_proof(succ),
            "root": self.root.hex(),
        }


# ============================================================
# CHECKPOINTS
# ============================================================

def build_checkpoint_proof(smts: List[SortedMerkleTree], start_index: int) -> List[Dict[str, Any]]:
    proof = []
    for i in range(start_index, len(smts) - 1):
        proof.append({
            "tree_index": i,
            "root": smts[i].root.hex(),
            "gamma_in_next_tree": smts[i + 1].original_leaves[0].hex(),
            "next_root": smts[i + 1].root.hex(),
        })
    return proof


def checkpoint_proof_construct(digests: List[bytes]) -> Tuple[List[SortedMerkleTree], List[Dict[str, Any]], str]:
    smts = []
    trees_json = []

    idx = 0
    prev_root = None

    while idx < len(digests):
        if prev_root is None:
            chunk = digests[idx: idx + LEAVES_PER_TREE]
            idx += len(chunk)
        else:
            chunk = [prev_root] + digests[idx: idx + LEAVES_PER_TREE - 1]
            idx += LEAVES_PER_TREE - 1

        smt = SortedMerkleTree(chunk)

        trees_json.append({
            "unsorted_leaves": [leaf.hex() for leaf in chunk],
            "sorted_leaves": [leaf.hex() for leaf in smt.leaves],
            "root": smt.root.hex(),
            "gamma": chunk[0].hex() if prev_root is not None else None,
            "prev_root": prev_root.hex() if prev_root is not None else None,
        })

        smts.append(smt)
        prev_root = smt.root

    return smts, trees_json, smts[-1].root.hex()


# ============================================================
# CASE 1 / CASE 2
# ============================================================

def case_1_open_open(smts: List[SortedMerkleTree], digests: List[bytes]) -> Dict[str, Any]:
    d = next(x for x in digests if x[:1] == b"O")
    for i, smt in enumerate(smts):
        if d in smt.leaves:
            return {
                "digest": d.hex(),
                "tree_index": i,
                "membership_proof": smt.membership_proof(d),
                "checkpoint_proof": build_checkpoint_proof(smts, i),
            }
    raise ValueError("No opening digest found")


def case_2_open_close(smts: List[SortedMerkleTree], digests: List[bytes]) -> Optional[Dict[str, Any]]:
    for d in digests:
        if d[:1] != b"O":
            continue

        c = flip_flag(d)
        open_tree = None
        close_tree = None

        for i, smt in enumerate(smts):
            if open_tree is None and d in smt.leaves:
                open_tree = i
            if close_tree is None and c in smt.leaves:
                close_tree = i

        if open_tree is not None and close_tree is not None and close_tree > open_tree:
            return {
                "open_digest": d.hex(),
                "close_digest": c.hex(),
                "open_tree": open_tree,
                "close_tree": close_tree,
                "open_proof": smts[open_tree].membership_proof(d),
                "close_proof": smts[close_tree].membership_proof(c),
                "open_checkpoint_proof": build_checkpoint_proof(smts, open_tree),
                "close_checkpoint_proof": build_checkpoint_proof(smts, close_tree),
            }

    return None


# ============================================================
# CASE 3: DNE
# ============================================================

def make_query_before_first(tree: SortedMerkleTree) -> bytes:
    smallest = tree.leaves[0]
    return b"\x00" * len(smallest)


def make_query_after_last(tree: SortedMerkleTree) -> bytes:
    largest = tree.leaves[-1]
    return b"\xff" * len(largest)


def make_query_between(a: bytes, b: bytes) -> Optional[bytes]:
    ai = int.from_bytes(a, "big")
    bi = int.from_bytes(b, "big")
    if bi - ai <= 1:
        return None
    mid = (ai + bi) // 2
    q = mid.to_bytes(len(a), "big")
    if a < q < b:
        return q
    return None


def find_same_subtree_gap(tree: SortedMerkleTree) -> Optional[Tuple[bytes, int]]:
    for pos in range(1, len(tree.leaves)):
        left_idx = pos - 1
        right_idx = pos
        if left_idx // 2 == right_idx // 2:
            q = make_query_between(tree.leaves[left_idx], tree.leaves[right_idx])
            if q is not None:
                return q, pos
    return None


def find_same_parent_subtrees_gap(tree: SortedMerkleTree) -> Optional[Tuple[bytes, int]]:
    for pos in range(1, len(tree.leaves)):
        left_idx = pos - 1
        right_idx = pos
        if left_idx // 2 != right_idx // 2 and left_idx // 4 == right_idx // 4:
            q = make_query_between(tree.leaves[left_idx], tree.leaves[right_idx])
            if q is not None:
                return q, pos
    return None


def case_3_dne(smts: List[SortedMerkleTree]) -> Dict[str, Any]:
    results = {}

    # before first leaf
    t0 = smts[0]
    q_before = make_query_before_first(t0)
    results["before_first_leaf"] = {
        "tree_index": 0,
        "query_digest": q_before.hex(),
        "dne_merkle_proof": t0.non_membership_proof(q_before),
        "checkpoint_proof": build_checkpoint_proof(smts, 0),
    }

    # between leaves of the same subtree
    same_subtree_result = None
    for i, smt in enumerate(smts):
        gap = find_same_subtree_gap(smt)
        if gap is not None:
            q, _ = gap
            same_subtree_result = {
                "tree_index": i,
                "query_digest": q.hex(),
                "dne_merkle_proof": smt.non_membership_proof(q),
                "checkpoint_proof": build_checkpoint_proof(smts, i),
            }
            break
    results["between_leaves_same_subtree"] = same_subtree_result

    # between two different subtrees sharing the same parent
    same_parent_subtrees_result = None
    for i, smt in enumerate(smts):
        gap = find_same_parent_subtrees_gap(smt)
        if gap is not None:
            q, _ = gap
            same_parent_subtrees_result = {
                "tree_index": i,
                "query_digest": q.hex(),
                "dne_merkle_proof": smt.non_membership_proof(q),
                "checkpoint_proof": build_checkpoint_proof(smts, i),
            }
            break
    results["between_two_subtrees_same_parent"] = same_parent_subtrees_result

    # after last leaf
    last_idx = len(smts) - 1
    last_tree = smts[last_idx]
    q_after = make_query_after_last(last_tree)
    results["after_last_leaf"] = {
        "tree_index": last_idx,
        "query_digest": q_after.hex(),
        "dne_merkle_proof": last_tree.non_membership_proof(q_after),
        "checkpoint_proof": build_checkpoint_proof(smts, last_idx),
    }

    return results


# ============================================================
# DATASET GENERATION
# ============================================================

def fake_prev_txid(tag: str, idx: int) -> bytes:
    return hash256(f"{tag}-{idx}".encode())


def generate_open_transactions(num_open: int) -> Tuple[List[BitcoinStyleTransaction], List[Tuple[SigningKey, Any, SigningKey, Any]]]:
    txs = []
    keys = []
    for i in range(num_open):
        sk1, vk1 = generate_keypair()
        sk2, vk2 = generate_keypair()

        tx = create_opening_transaction(
            funder_sk=sk1,
            funder_vk=vk1,
            counterparty_vk=vk2,
            prev_txid=fake_prev_txid("funding-utxo", i),
            prev_vout=0,
            utxo_value_sat=1_500_000,
            channel_value_sat=1_200_000,
            fee_sat=2_000,
        )
        txs.append(tx)
        keys.append((sk1, vk1, sk2, vk2))
    return txs, keys


def generate_close_transactions(num_close: int) -> List[BitcoinStyleTransaction]:
    txs = []
    for i in range(num_close):
        sk1, vk1 = generate_keypair()
        sk2, vk2 = generate_keypair()

        temp_open = create_opening_transaction(
            funder_sk=sk1,
            funder_vk=vk1,
            counterparty_vk=vk2,
            prev_txid=fake_prev_txid("independent-close-open", i),
            prev_vout=0,
            utxo_value_sat=1_500_000,
            channel_value_sat=1_200_000,
            fee_sat=2_000,
        )
        close_tx = create_closing_transaction(
            open_tx=temp_open,
            vk1=vk1,
            sk1=sk1,
            vk2=vk2,
            sk2=sk2,
            payout1_sat=600_000,
            payout2_sat=598_500,
            fee_sat=1_500,
        )
        txs.append(close_tx)
    return txs


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    open_txs, open_keys = generate_open_transactions(NUM_OPEN)
    close_txs = generate_close_transactions(NUM_CLOSE)

    open_digests = [compute_digest_from_transaction(tx, b"O") for tx in open_txs]
    close_digests = [compute_digest_from_transaction(tx, b"C") for tx in close_txs]
    digests = open_digests + close_digests

    # force one valid OPEN -> CLOSE pair
    forced_sk1, forced_vk1, forced_sk2, forced_vk2 = open_keys[10]
    forced_open_tx = open_txs[10]
    forced_close_tx = create_closing_transaction(
        open_tx=forced_open_tx,
        vk1=forced_vk1,
        sk1=forced_sk1,
        vk2=forced_vk2,
        sk2=forced_sk2,
        payout1_sat=600_000,
        payout2_sat=598_500,
        fee_sat=1_500,
    )
    close_txs[300] = forced_close_tx
    digests[10] = compute_digest_from_transaction(forced_open_tx, b"O")
    digests[NUM_OPEN + 300] = compute_digest_from_transaction(forced_close_tx, b"C")

    smts, trees_json, checkpoint_root = checkpoint_proof_construct(digests)

    output = {
        "transactions": {
            "open": [
                {
                    "index": i,
                    "transaction": tx.to_json(),
                    "digest": digests[i].hex(),
                }
                for i, tx in enumerate(open_txs)
            ],
            "close": [
                {
                    "index": i,
                    "transaction": tx.to_json(),
                    "digest": digests[NUM_OPEN + i].hex(),
                }
                for i, tx in enumerate(close_txs)
            ],
        },
        "trees": trees_json,
        "checkpoint_root": checkpoint_root,
        "case_1_open_open": case_1_open_open(smts, digests),
        "case_2_open_close": case_2_open_close(smts, digests),
        "case_3_dne": case_3_dne(smts),
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)
