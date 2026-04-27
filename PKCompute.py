import json
import secrets
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

from py_ecc.secp256k1.secp256k1 import G, N, add, multiply

# ============================================================
# Types
# ============================================================

Point = Tuple[int, int]


# ============================================================
# Basic helpers
# ============================================================

def generate_nonzero_scalar() -> int:
    while True:
        x = secrets.randbelow(N)
        if x != 0:
            return x


def point_to_json(pt: Point) -> Dict[str, str]:
    return {
        "x": str(pt[0]),
        "y": str(pt[1]),
    }


def point_to_bytes(pt: Point) -> bytes:
    x, y = pt
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def hash_to_scalar(*parts: bytes, dst: bytes) -> int:
    h = hashlib.sha256()
    h.update(dst)
    for part in parts:
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)

    out = int.from_bytes(h.digest(), "big") % N
    return out if out != 0 else 1


def hagg_Lj_Xj(L_j: List[Point], X_j: Point) -> int:
    encoded_Lj = b"".join(point_to_bytes(P) for P in L_j)
    return hash_to_scalar(encoded_Lj, point_to_bytes(X_j), dst=b"AVIS_H1_HAGG_V1")


def h2_commit(R_jk: Point) -> str:
    digest = hashlib.sha256(b"AVIS_H2_COMMIT_V1" + point_to_bytes(R_jk)).hexdigest()
    return digest


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


# ============================================================
# EC protocol operations
# ============================================================

def compute_public_contribution(x_jk: int) -> Point:
    return multiply(G, x_jk)


def compute_nonce_point(r_jk: int) -> Point:
    return multiply(G, r_jk)


def compute_PK_j(L_j: List[Point], a_j: int) -> Point:
    sum_points: Optional[Point] = None

    for X_jk in L_j:
        if sum_points is None:
            sum_points = X_jk
        else:
            sum_points = add(sum_points, X_jk)

    if sum_points is None:
        raise ValueError("L_j is empty; cannot compute PK_j.")

    return multiply(sum_points, a_j)


# ============================================================
# Transaction signing helpers
# ============================================================

def hash_tx_to_scalar(tx: Dict[str, Any], R: Point, vk: Point) -> int:
    tx_bytes = json.dumps(tx, sort_keys=True).encode("utf-8")

    h = hashlib.sha256()
    h.update(b"AVIS_TX_SIGN_V1")
    h.update(point_to_bytes(R))
    h.update(point_to_bytes(vk))
    h.update(tx_bytes)

    e = int.from_bytes(h.digest(), "big") % N
    return e if e != 0 else 1


def sign_tx_tuple(tx: Dict[str, Any], sk: int, vk: Point) -> Dict[str, Any]:
    """
    Schnorr-style signature:
        R = rG
        e = H(R, vk, tx)
        s = r + e*sk mod N
    """
    r = generate_nonzero_scalar()
    R = multiply(G, r)

    e = hash_tx_to_scalar(tx, R, vk)
    s = (r + e * sk) % N

    return {
        "R": point_to_json(R),
        "s": str(s),
        "challenge_e": str(e),
    }


# ============================================================
# Timing helper for ONE auditor public key computation
# ============================================================

def time_single_auditor_public_key(
    public_matrix_X: List[List[Point]],
    auditor_index: int
) -> Tuple[Point, int, float]:

    start_time = time.perf_counter()

    L_j = public_matrix_X[auditor_index]
    X_j = public_matrix_X[auditor_index][auditor_index]
    a_j = hagg_Lj_Xj(L_j, X_j)
    PK_j = compute_PK_j(L_j, a_j)

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time

    return PK_j, a_j, elapsed_time


# ============================================================
# Main protocol
# ============================================================

def generate_protocol1_keys_with_commitments(
    num_auditors: int,
    auditor_to_time: int = 1,
    out_dir: str = "protocol1_data"
) -> None:

    if auditor_to_time < 1 or auditor_to_time > num_auditors:
        raise ValueError(
            f"auditor_to_time must be between 1 and {num_auditors}, got {auditor_to_time}"
        )

    auditor_index = auditor_to_time - 1

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    secret_matrix_x: List[List[int]] = []
    public_matrix_X: List[List[Point]] = []

    nonce_matrix_r: List[List[int]] = []
    nonce_point_matrix_R: List[List[Point]] = []
    commit_matrix_t: List[List[str]] = []

    # --------------------------------------------------------
    # Phase 1: Public contribution setup
    # --------------------------------------------------------
    for j in range(num_auditors):
        x_row: List[int] = []
        X_row: List[Point] = []

        for k in range(num_auditors):
            x_jk = generate_nonzero_scalar()
            X_jk = compute_public_contribution(x_jk)

            x_row.append(x_jk)
            X_row.append(X_jk)

        secret_matrix_x.append(x_row)
        public_matrix_X.append(X_row)

    # --------------------------------------------------------
    # Phase 2: Nonce/commitment setup
    # --------------------------------------------------------
    verification_results_by_auditor: List[Dict[str, bool]] = []

    for j in range(num_auditors):
        r_row: List[int] = []
        R_row: List[Point] = []
        t_row: List[str] = []

        verification_map: Dict[str, bool] = {}

        for k in range(num_auditors):
            r_jk = generate_nonzero_scalar()
            R_jk = compute_nonce_point(r_jk)
            t_jk = h2_commit(R_jk)

            verified = (t_jk == h2_commit(R_jk))
            verification_map[f"from_auditor_{k + 1}"] = verified

            r_row.append(r_jk)
            R_row.append(R_jk)
            t_row.append(t_jk)

        nonce_matrix_r.append(r_row)
        nonce_point_matrix_R.append(R_row)
        commit_matrix_t.append(t_row)
        verification_results_by_auditor.append(verification_map)

    # --------------------------------------------------------
    # Phase 3: Time ONE auditor's public key computation
    # --------------------------------------------------------
    PK_j, a_j, pk_time = time_single_auditor_public_key(
        public_matrix_X=public_matrix_X,
        auditor_index=auditor_index
    )

    print(
        f"\nTime to compute public key for auditor {auditor_to_time}: "
        f"{pk_time:.6f} seconds"
    )

    # --------------------------------------------------------
    # Construct tx tuple and sign with sk_auditor
    # --------------------------------------------------------
    sk_auditor = secret_matrix_x[auditor_index][auditor_index]
    vk_auditor = public_matrix_X[auditor_index][auditor_index]

    tx_tuple = {
        "source": point_to_json(vk_auditor),
        "destination": point_to_json(PK_j),
        "amount": "50000 BTC",
    }

    tx_signature = sign_tx_tuple(
        tx=tx_tuple,
        sk=sk_auditor,
        vk=vk_auditor
    )

    # --------------------------------------------------------
    # Save chosen auditor record
    # --------------------------------------------------------
    L_j = public_matrix_X[auditor_index]
    X_j = public_matrix_X[auditor_index][auditor_index]

    auditor_record = {
        "auditor_id": auditor_to_time,
        "phase_1_public_contributions": {
            f"from_auditor_{k + 1}": point_to_json(public_matrix_X[auditor_index][k])
            for k in range(num_auditors)
        },
        "phase_2_nonce_points": {
            f"from_auditor_{k + 1}": point_to_json(nonce_point_matrix_R[auditor_index][k])
            for k in range(num_auditors)
        },
        "phase_2_commitments": {
            f"from_auditor_{k + 1}": commit_matrix_t[auditor_index][k]
            for k in range(num_auditors)
        },
        "phase_2_commitment_verification": verification_results_by_auditor[auditor_index],
        "X_j_used_in_hash": point_to_json(X_j),
        "hash_coefficient": {
            f"a_{auditor_to_time}": str(a_j)
        },
        "aggregated_public_key_PK_j": point_to_json(PK_j),
        "public_key_computation_time_seconds": pk_time,

        "transaction_tuple": tx_tuple,
        "transaction_signature_by_auditor": tx_signature,
    }

    save_json(out_path / f"auditor_{auditor_to_time}.json", auditor_record)

    # --------------------------------------------------------
    # Save contributor files
    # --------------------------------------------------------
    for k in range(num_auditors):
        contributor_record = {
            "contributor_id": k + 1,
            "secret_contributions_x": {
                f"for_auditor_{j + 1}": str(secret_matrix_x[j][k])
                for j in range(num_auditors)
            },
            "public_contributions_X": {
                f"for_auditor_{j + 1}": point_to_json(public_matrix_X[j][k])
                for j in range(num_auditors)
            },
            "nonce_secrets_r": {
                f"for_auditor_{j + 1}": str(nonce_matrix_r[j][k])
                for j in range(num_auditors)
            },
            "nonce_points_R": {
                f"for_auditor_{j + 1}": point_to_json(nonce_point_matrix_R[j][k])
                for j in range(num_auditors)
            },
            "commitments_t": {
                f"for_auditor_{j + 1}": commit_matrix_t[j][k]
                for j in range(num_auditors)
            },
        }

        save_json(out_path / f"contributor_{k + 1}.json", contributor_record)

    # --------------------------------------------------------
    # Save full matrix files
    # --------------------------------------------------------
    matrix_secret_x_json = {
        f"auditor_{j + 1}": {
            f"from_auditor_{k + 1}": str(secret_matrix_x[j][k])
            for k in range(num_auditors)
        }
        for j in range(num_auditors)
    }
    save_json(out_path / "matrix_secret_contributions_x.json", matrix_secret_x_json)

    matrix_public_X_json = {
        f"auditor_{j + 1}": {
            f"from_auditor_{k + 1}": point_to_json(public_matrix_X[j][k])
            for k in range(num_auditors)
        }
        for j in range(num_auditors)
    }
    save_json(out_path / "matrix_public_contributions_X.json", matrix_public_X_json)

    matrix_nonce_r_json = {
        f"auditor_{j + 1}": {
            f"from_auditor_{k + 1}": str(nonce_matrix_r[j][k])
            for k in range(num_auditors)
        }
        for j in range(num_auditors)
    }
    save_json(out_path / "matrix_nonce_secrets_r.json", matrix_nonce_r_json)

    matrix_nonce_R_json = {
        f"auditor_{j + 1}": {
            f"from_auditor_{k + 1}": point_to_json(nonce_point_matrix_R[j][k])
            for k in range(num_auditors)
        }
        for j in range(num_auditors)
    }
    save_json(out_path / "matrix_nonce_points_R.json", matrix_nonce_R_json)

    matrix_commit_t_json = {
        f"auditor_{j + 1}": {
            f"from_auditor_{k + 1}": commit_matrix_t[j][k]
            for k in range(num_auditors)
        }
        for j in range(num_auditors)
    }
    save_json(out_path / "matrix_commitments_t.json", matrix_commit_t_json)

    matrix_verify_json = {
        f"auditor_{j + 1}": verification_results_by_auditor[j]
        for j in range(num_auditors)
    }
    save_json(out_path / "matrix_commitment_verification.json", matrix_verify_json)

    chosen_pk_json = {
        f"auditor_{auditor_to_time}": point_to_json(PK_j)
    }
    save_json(out_path / "timed_auditor_public_key.json", chosen_pk_json)

    metadata = {
        "curve": "secp256k1",
        "group_order_N": str(N),
        "generator_G": point_to_json(G),
        "num_auditors": num_auditors,
        "timed_auditor": auditor_to_time,
        "phase_order": [
            "Phase 1: public contributions",
            "Phase 2: nonce commitments and verification",
            "Phase 3: single-auditor public key computation timing",
            "Phase 4: transaction tuple signing"
        ],
        "transaction_description": {
            "source": "vk_auditor",
            "destination": "PK_auditor",
            "amount": "50000 BTC",
            "signed_with": "sk_auditor"
        },
    }
    save_json(out_path / "metadata.json", metadata)

    print(f"\nGenerated protocol data in: {out_path.resolve()}")
    print(f"\nSaved timed public key computation and signed transaction for auditor {auditor_to_time}")


def timed_run(
    num_auditors: int = 10,
    auditor_to_time: int = 1,
    out_dir: str = "protocol1_data"
) -> float:

    start_time = time.perf_counter()

    generate_protocol1_keys_with_commitments(
        num_auditors=num_auditors,
        auditor_to_time=auditor_to_time,
        out_dir=out_dir
    )

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time

    print(f"\nTotal execution time of full run: {elapsed_time:.6f} seconds")
    return elapsed_time


# ============================================================
# Run
# ============================================================

if __name__ == "__main__":
    timed_run(
        num_auditors=150,
        auditor_to_time=1,
        out_dir="protocol1_data"
    )
