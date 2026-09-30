# Cross-Dataset Transfer Report (generated)

Experiment ID: `EXP-P1-TRANSFER-CSE-TO-UNSW-001`
Source Dataset: `cse_cic_ids2018` · Target Dataset: `unsw_nb15`
Target Status: `DATA_NOT_AVAILABLE`

## Programmatic Common Transfer Contract

To evaluate cross-dataset generalizability without fabricating features or proxies,
the transfer feature contract is computed via programmatic intersection of source and target semantic mappings:

$$F_{transfer} = F_{source} \cap F_{target}$$

- **Common Transfer Features (4 Features)**:
  1. `flow_duration_ms`
  2. `flow_pkts_per_s`
  3. `flow_bytes_per_s`
  4. `fwd_packets_count`

## Unsupported Target Features (UNSW-NB15)

The following 6 features from the in-domain R10 contract are **NOT** supported by UNSW-NB15:
- `syn_flag_count`
- `ack_flag_count`
- `rst_flag_count`
- `fin_flag_count`
- `syn_ack_ratio`
- `pkt_len_std`

> [!IMPORTANT]
> In accordance with Phase-1 scientific rules, these features are marked `UNSUPPORTED`.
> No artificial proxy values were fabricated. The source model was trained strictly on the 4-feature contract.

## Instructions to Complete Empirical Target Evaluation

1. Place official UNSW-NB15 CSV files into `data/raw/unsw_nb15/`.
2. Register the dataset:
   ```bash
   python scripts/phase1/prepare_dataset.py register --dataset unsw_nb15 --file data/raw/unsw_nb15/<filename>.csv
   ```
3. Re-run transfer evaluation:
   ```bash
   python scripts/phase1/run_experiment.py --config configs/experiments/p1_transfer_cse_to_unsw.yaml
   ```
