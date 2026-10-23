# Model Card

## Model Identity

| Field | Value |
|-------|-------|
| Name | phishguard-url-rf |
| Version | 1.0.0 |
| Algorithm | XGBoost |
| Framework | scikit-learn 1.6.1 + XGBoost |
| Training date | 2026-10-21 |
| Random seed | 42 |
| Feature count | 35 |
| Schema version | 1.0.0 |

## Objective

Classify submitted URLs as legitimate (SAFE) or phishing (SUSPICIOUS/DLEXIC) based on 35 lexical URL features. The model does NOT fetch or execute any content — it operates entirely on the URL string structure.

## Performance (Held-Out Test Set)

| Metric | Value |
|--------|-------|
| Accuracy | 93.74% |
| Precision | 94.73% |
| Recall | 92.67% |
| F1 | 93.69% |
| F1 (macro) | 93.74% |
| FPR (at safe threshold) | 5.18% |
| FNR (at dangerous threshold) | 7.33% |
| Specificity | 94.82% |
| Sensitivity | 92.67% |

### Confusion Matrix

|              | Predicted Legitimate | Predicted Phishing |
|-------------|----------------------|-------------------|
| Actual Legit | 32,087               | 1,752             |
| Actual Phish | 2,490                | 31,466            |

### Thresholds

| Threshold | Value | FPR Constraint | Status |
|-----------|-------|----------------|--------|
| Safe (suspicious) | 0.625 | ≤ 5.0% | Met |
| Dangerous | 0.895 | ≤ 2.0% | Met |

## Feature Importance

Top 5 features (by global importance):

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | uses_https | 0.565 |
| 2 | url_keyword_count | 0.123 |
| 3 | suspicious_keyword_count | 0.089 |
| 4 | brand_impersonation_count | 0.076 |
| 5 | known_shortener_count | 0.054 |

Full importance array: 35 features in `ml/artifacts/model_metrics.json`.

## Limitations

1. **URL-only analysis.** The model sees only the URL string structure. It cannot detect phishing that relies on page content, JavaScript, or social engineering.
2. **Lexical features only.** No semantic understanding of the URL meaning.
3. **Static model.** The model is frozen at version 1.0.0. New phishing patterns may emerge that the model hasn't seen.
4. **No zero-day detection.** The model cannot detect previously unseen phishing techniques.
5. **False positives.** ~5% of legitimate URLs are flagged as suspicious. Users should exercise caution.
6. **False negatives.** ~7% of phishing URLs are missed. Users should not trust a "safe" verdict without verification.
7. **No temporal drift handling.** The model was trained on a snapshot; performance may degrade over time.

## Ethical Considerations

- The system is a **decision support tool**, not a definitive safety guarantee.
- Every verdict includes limitations and guidance text.
- The frontend explicitly warns: "This is an automated assessment, not a guarantee that a site is safe."
- Failed scans never produce a "safe" verdict.
- Dangerous verdicts advise against entering credentials or payment details.
