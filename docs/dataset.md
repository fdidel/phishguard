# Dataset

## Source

**Hassan-Albattra/URL_Phishing_Detection_Dataset**

- License: MIT
- GitHub: https://github.com/Hassan-Albattra/URL_Phishing_Detection_Dataset
- Raw data: CSV with columns `url`, `label` (0=legitimate, 1=phishing)

## Records Used

| Metric | Value |
|--------|-------|
| Total records | 338,358 |
| Legitimate (label=0) | 170,000 |
| Phishing (label=1) | 168,358 |
| Phishing ratio | 49.76% |
| Imbalance ratio | 1.01:1 |

## Preprocessing

1. Loaded CSV via pandas
2. Dropped rows with missing `url` or `label`
3. Converted labels to int (0/1)
4. Verified class balance (imbalance ratio < 1.05)

## Feature Extraction

35 lexical features extracted from each URL using `phishguard/feature_extraction.py`:

| Category | Features |
|----------|----------━|
| Scheme | uses_https, non_https_scheme |
| Length | url_length, hostname_length, tld_length, path_length, query_length, fragment_length |
| Structure | dot_count, dash_count, hyphen_count, underscore_count, at_symbol_userinfo, double_slash_redirect, explicit_port, ip_address_host |
| Keywords | url_keyword_count, suspicious_keyword_count, brand_impersonation_count, known_shortener_count |
| TLD | risky_tld_count |
| Domain | registrable_domain_length, subdomain_depth |

## Split Strategy

- **Train:** 202,813 rows (60%)
- **Validation:** 67,750 rows (20%)
- **Test:** 67,795 rows (20%)
- **Strategy:** GroupShuffleSplit by registrable domain (prevents data leakage)
- **Class balance verified** on each split

## Reproducibility

- Random seed: 42
- All splits deterministic given the seed
- Model artifact: `ml/artifacts/phishguard_model.joblib` (versioned)
- Metrics: `ml/artifacts/model_metrics.json` (frozen, no retraining)
