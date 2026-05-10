"""
Figure 4: Temporal stability of six Tier 1 features across compile-year cohorts.
Reproduces Figure 4 from the paper.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("../data/pe_features_v4.csv")
df = df[df["is_malware"] == 1].copy()

tier1_features = [
    ("checksum_is_zero",          "PE checksum zero"),
    ("rwx_section_flag",          "RWX section"),
    ("has_dynamic_api_strings",   "Dynamic API strings"),
    ("anti_analysis_imports_flag","Anti-analysis imports"),
    ("high_entropy_flag",         "High entropy section"),
    ("has_network_strings",       "Network/C2 strings"),
]

era_order = ["pre_2015", "2015_2019", "2020_2022", "2023_plus"]
era_labels = ["<2015", "2015–2019", "2020–2022", "2023+"]

# Normalise bucket names
df["temporal_bucket"] = df["temporal_bucket"].str.replace("pre-2015", "pre_2015", regex=False)

fig, axes = plt.subplots(2, 3, figsize=(14, 8), sharey=True)
axes = axes.flatten()

for ax, (col, label) in zip(axes, tier1_features):
    for family in df["family"].unique():
        fdf = df[df["family"] == family]
        rates, eras_plot = [], []
        for era, era_label in zip(era_order, era_labels):
            subset = fdf[fdf["temporal_bucket"] == era]
            if len(subset) >= 3:
                rates.append(subset[col].mean() * 100)
                eras_plot.append(era_label)
        if rates:
            ax.plot(eras_plot, rates, marker="o", label=family, linewidth=1.5)

    ax.set_title(label, fontsize=10)
    ax.set_ylim(0, 105)
    ax.set_ylabel("Prevalence (%)" if ax in [axes[0], axes[3]] else "")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=20, ha="right", fontsize=8)
    ax.axhline(80, color="grey", linestyle=":", linewidth=1, alpha=0.7)
    ax.grid(alpha=0.3)

# Shared legend
handles, labels_leg = axes[0].get_legend_handles_labels()
fig.legend(handles, labels_leg, loc="lower center", ncol=5, fontsize=9,
           bbox_to_anchor=(0.5, -0.03))

fig.suptitle(
    "Figure 4. Temporal stability of six Tier 1 features across compile-year cohorts.\n"
    "Dotted line at 80% = Tier 1 threshold. Points omitted where cohort n < 3.",
    fontsize=10
)
plt.tight_layout(rect=[0, 0.06, 1, 1])
plt.savefig("fig4_temporal_stability.png", dpi=150, bbox_inches="tight")
print("Saved fig4_temporal_stability.png")
plt.show()
