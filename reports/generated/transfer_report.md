# Cross-Dataset Transfer Report (generated)

Experiment ID: `EXP-P1-TRANSFER-CSE-TO-UNSW-001`
Source Dataset: `cse_cic_ids2018` · Target Dataset: `unsw_nb15`
Target Status: `AVAILABLE (VERIFIED)`

## Programmatic Common Transfer Contract

To evaluate cross-dataset generalizability without fabricating features or proxies,
the transfer feature contract is computed via programmatic intersection of source and target semantic mappings:

$$F_{transfer} = F_{source} \cap F_{target}$$

- **Common Transfer Features (4 Features)**:
  1. `flow_duration_ms`
  2. `flow_packets_per_s`
  3. `flow_bytes_per_s`
  4. `packet_length_mean`

## Unsupported Target Features (UNSW-NB15)

The following 6 features from the in-domain R10 contract are **NOT** supported by UNSW-NB15:
- `packet_length_std`
- `syn_count`
- `ack_count`
- `rst_count`
- `fin_count`
- `syn_ack_ratio`

> [!IMPORTANT]
> In accordance with Phase-1 scientific rules, these features are marked `UNSUPPORTED`.
> No artificial proxy values were fabricated. The source model was trained strictly on the common feature contract.

## Instructions to Complete Empirical Target Evaluation

Both source (CSE-CIC-IDS2018) and target (UNSW-NB15) datasets are acquired and verified locally.
To execute transfer evaluation:
```bash
python scripts/phase1/run_experiment.py --config configs/experiments/p1_transfer_cse_to_unsw.yaml
```
