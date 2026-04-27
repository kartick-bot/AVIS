
This repository contains Python implementations for the paper titled AVIS: Authenticating and Verifying Nodes In a Distributed Network
1. Publicompute.py -- contains the code for public key computation and the stake transaction tuple signing
2. Merkle.py -- contains the code for the Merkle tree experiments 

------------------------------------------------------------------
## Requirements

Use Python 3.10 or higher.

Install dependencies:

```bash
pip3 install py-ecc
pip install matplotlib numpy pandas seaborn
```
Running Public key computation 
```bash
python3 PKCompute.py
```
After running protocol1.py, the output directory contains files such as:
protocol1_data/
├── auditor_1.json
├── contributor_1.json
├── contributor_2.json
├── ...
├── matrix_secret_contributions_x.json
├── matrix_public_contributions_X.json
├── matrix_nonce_secrets_r.json
├── matrix_nonce_points_R.json
├── matrix_commitments_t.json
├── matrix_commitment_verification.json
├── timed_auditor_public_key.json
└── metadata.json
-------------------------------------------------
Running the Merkle Tree Code
```bash
python3 Merkletree21.py -- for 2^10 leaves
```

