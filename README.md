# Structural Packer Invariants as Forensic Indicators for Polymorphic Malware Attribution

> **A Cross-Family Visibility Framework with Machine Learning Validation**

[![Paper](https://img.shields.io/badge/Paper-Link%20Coming%20Soon-lightgrey)](.)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Dataset](https://img.shields.io/badge/Data-MalwareBazaar-red)](https://bazaar.abuse.ch)

---

## Overview

This repository contains the dataset, analysis pipeline, and results for a systematic static analysis framework that identifies **structurally stable packer invariants** across nine malware families — without execution or unpacking.

Hash-based identification fails against polymorphic malware. This work shows that the **PE file format itself** creates a forensic opportunity that persists despite payload encryption: packing mechanisms must configure PE containers in physically constrained ways, leaving measurable structural fingerprints that are stable across variants.

### Key Results

| Metric | Value |
|--------|-------|
| Families analysed | 9 (Sality, Virut, Emotet, Trickbot, Formbook, Lumma, Upatre, Zeus) |
| Total samples | 362 (316 malware, 46 benign) |
| Features extracted per binary | 99 across 7 structural groups |
| Tier 1 indicators identified | 13 (≥80% visibility, ≤10% FPR) |
| XGBoost ROC-AUC (SOREL-20M, 100k samples) | **0.9961** |
| Pairwise comparisons (BH-corrected) | 1,152 |

---

## Repository Structure

```
.
├── README.md
├── LICENSE
├── requirements.txt
│
├── data/
│   └── pe_features_v4.csv          # 362-sample feature matrix (99 features/binary)
│
├── figures/                        # Reproducible figure scripts
│   ├── fig1_feature_heatmap.py
│   ├── fig2_triage_score_bar.py
│   ├── fig3_numeric_features.py
│   ├── fig4_temporal_stability.py
│   └── fig5_discriminability_scatter.py
│
└── results/
    └── tier1_visibility_matrix.csv # Table 1 data
```

---

## Dataset: `pe_features_v4.csv`

The main dataset contains **362 PE binaries** (363 rows including header) with **99 extracted features** per binary, spanning seven analytical groups:

| Group | Features | Description |
|-------|----------|-------------|
| A — File Identifiers | File size, entropy, architecture, compile timestamp | Whole-file properties |
| B — PE Header Fields | Checksum, ASLR, DEP, entry point RVA, image base | Optional header & DLL characteristics |
| C — Section Characteristics | High entropy flag, RWX flag, raw/virtual mismatch, section count | Per-section aggregates |
| D — Import/Export Tables | Import count, unpacking/injection/anti-analysis/network flags | Import directory analysis |
| E — Optional Directories | Digital signature, debug data, TLS callbacks, overlay data | PE data directory |
| F — String Signals | URLs, IPs, Base64, shell/registry/crypto/C2/mutex strings | Raw byte stream extraction |
| G — Composite Packing Score | 0–10 ordinal score aggregating 10 binary indicators | Triage summary metric |

### Key columns

| Column | Description |
|--------|-------------|
| `family` | Malware family label (or `benign`) |
| `sha256` | Sample hash (for verification against MalwareBazaar) |
| `is_malware` | 1 = malware, 0 = benign |
| `triage_score` | 0–100 composite score |
| `triage_tier` | CRITICAL / HIGH / MEDIUM / LOW |
| `family_match` | Top attributed family |
| `family_confidence` | STRONG / MODERATE / WEAK / UNKNOWN |
| `family_scores` | Full score breakdown across all 9 families |

### Sample source

Malware samples were obtained from [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch, 2023). Each sample was verified by SHA-256 integrity check, PE structural validity (pefile v2023.2.7), and VirusTotal consensus label (≥60% engine agreement). Benign samples are from a clean Windows 10 installation, supplemented by Pestudio v9.7.

> **Note:** Raw PE binaries are **not** included in this repository due to platform policies on distributing malware samples. Hashes in `sha256` column can be used to retrieve samples directly from MalwareBazaar.

---

## Reproducing the Figures

### Requirements

```bash
pip install -r requirements.txt
```

`requirements.txt` covers: `pandas`, `numpy`, `matplotlib`, `seaborn`, `scipy`, `scikit-learn`, `xgboost`.

### Figure 1 — Feature × Family Heatmap

```bash
python figures/fig1_feature_heatmap.py
```

Produces the Tier 1 visibility heatmap with FP% column (Table 1 visualised). Cell colour encodes prevalence 0–100%; FP% column uses green-to-red colouring.

### Figure 2 — Triage Score Distribution

```bash
python figures/fig2_triage_score_bar.py
```

Mean triage score (±1 SD) per family and benign baseline. The dashed red line marks the benign mean (31.7).

### Figure 3 — Numeric Feature Comparison

```bash
python figures/fig3_numeric_features.py
```

Three-panel figure: (A) file entropy, (B) packing score, (C) import count across families.

### Figure 4 — Temporal Stability

```bash
python figures/fig4_temporal_stability.py
```

Tier 1 feature prevalence across four compile-year cohorts: pre-2015, 2015–2019, 2020–2022, 2023+.

### Figure 5 — Feature Discriminability Scatter

```bash
python figures/fig5_discriminability_scatter.py
```

Each of 32 features plotted by mean malware prevalence (y) vs. benign FPR (x). Upper-left quadrant = highest-utility indicators.

---

## Three-Tier Forensic Attribution Framework

The framework connects feature visibility to investigation context:

| Tier | Visibility | FPR | Use |
|------|-----------|-----|-----|
| **Tier 1** | ≥80% in ≥1 family | ≤10% | Triage flag; ≥3 simultaneous indicators from ≥2 structural groups required for attribution |
| **Tier 2** | 50–79% | 10–30% | Supports Tier 1 in attribution arguments |
| **Tier 3** | <50% | >30% | Absence-as-evidence; retained for profile narrowing |

**Attribution confidence** is classified as STRONG when the top-matching family profile scores ≥70% AND leads the second-matching profile by ≥20 percentage points.

---

## The Pestudio Finding

A critical finding from the benign baseline: **Pestudio v9.7** — a legitimate PE analysis tool used by malware analysts worldwide — triggered at 100% on three Tier 1 indicators simultaneously (unpacking imports, anti-analysis imports, dynamic API name strings). This empirically demonstrates why **single-feature attribution is insufficient** regardless of tier classification. The anchor features for any attribution argument are PE checksum zero (Pestudio FPR: 0%) and RWX sections (Pestudio FPR: 0%).

---



---

## References

Key references used in this work:

- Anderson & Roth (2018). EMBER: An open dataset for training static PE malware machine learning models. *arXiv:1804.04637*
- Harang & Rudd (2020). SOREL-20M: A large scale benchmark dataset for malicious PE detection. *arXiv:2012.07634* — [GitHub](https://github.com/sophos/SOREL-20M)
- Ugarte-Pedrero et al. (2015). SoK: Deep packer inspection. *IEEE S&P 2015*
- Lyda & Hamrock (2007). Using entropy analysis to find encrypted and packed malware. *IEEE Security & Privacy*
- Benjamini & Hochberg (1995). Controlling the false discovery rate. *JRSS-B*

---

## License

This repository is released under the [MIT License](LICENSE). The dataset (`pe_features_v4.csv`) is released for academic research use. Malware sample hashes are provided solely for research reproduction purposes.
