"""
Figure 5: Feature discriminability scatter plot.
Each of 32 features plotted by mean malware prevalence (y) vs benign FPR (x).
Reproduces Figure 5 from the paper.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

df = pd.read_csv("../data/pe_features_v4.csv")

binary_features = [
    ("checksum_is_zero",           "PE checksum zero"),
    ("rwx_section_flag",           "RWX section"),
    ("no_protections",             "No ASLR/DEP"),
    ("anti_analysis_imports_flag", "Anti-analysis imports"),
    ("unpack_imports_flag",        "Unpacking imports"),
    ("has_dynamic_api_strings",    "Dynamic API strings"),
    ("dynamic_resolution_flag",    "Dynamic resolution flag"),
    ("has_network_strings",        "Network/C2 strings"),
    ("high_entropy_flag",          "High entropy section"),
    ("has_filepath_strings",       "Hardcoded file paths"),
    ("has_crypto_strings",         "Crypto-related strings"),
    ("has_base64_blobs",           "Base64 blobs"),
    ("has_overlay",                "Overlay data"),
    ("ep_is_in_last_section",      "EP in last section"),
    ("zero_imports",               "Zero imports"),
    ("few_imports_flag",           "Few imports (≤5)"),
    ("has_debug_directory",        "Debug directory"),
    ("has_tls",                    "TLS callbacks"),
    ("has_digital_signature",      "Digital signature"),
    ("has_exports",                "Has exports"),
    ("has_shell_strings",          "Shell command strings"),
    ("has_registry_strings",       "Registry path strings"),
    ("has_inject_strings",         "Injection strings"),
    ("has_mutex_strings",          "Mutex strings"),
    ("packer_section_detected",    "Known packer section"),
    ("suspicious_section_name",    "Suspicious section name"),
    ("raw_virtual_mismatch",       "Raw/virtual mismatch"),
    ("timestamp_anomaly",          "Timestamp anomaly"),
    ("has_aslr",                   "ASLR present"),
    ("has_dep",                    "DEP present"),
    ("inject_imports_flag",        "Injection imports"),
    ("has_bound_imports",          "Bound imports"),
]

malware_df = df[df["is_malware"] == 1]
benign_df  = df[df["is_malware"] == 0]

fig, ax = plt.subplots(figsize=(10, 8))

# Background shading for high-utility zone
ax.axvspan(0, 30, ymin=0.5, ymax=1.0,
           alpha=0.08, color="green", label="High-utility zone")
ax.axvline(30, color="green", linestyle="--", linewidth=0.8, alpha=0.5)
ax.axhline(50, color="green", linestyle="--", linewidth=0.8, alpha=0.5)

tier1_cols = {f[0] for f in binary_features[:13]}  # first 13 are Tier 1

for col, label in binary_features:
    if col not in df.columns:
        continue
    mal_prev = malware_df[col].mean() * 100
    fp_rate  = benign_df[col].mean() * 100

    is_t1 = (col in tier1_cols) and mal_prev >= 80
    colour = "#c0392b" if is_t1 else "#7f8c8d"
    size   = 80 if is_t1 else 40
    marker = "*" if is_t1 else "o"

    ax.scatter(fp_rate, mal_prev, color=colour, s=size, marker=marker,
               zorder=3, alpha=0.85)

    if is_t1 or fp_rate < 15 or mal_prev > 85:
        ax.annotate(
            label, (fp_rate, mal_prev),
            textcoords="offset points", xytext=(5, 3),
            fontsize=7, color=colour,
            arrowprops=dict(arrowstyle="-", color="grey", lw=0.5)
        )

ax.set_xlabel("False Positive Rate in Benign Baseline (%)", fontsize=11)
ax.set_ylabel("Mean Prevalence Across Malware Families (%)", fontsize=11)
ax.set_xlim(-3, 103)
ax.set_ylim(-3, 108)
ax.set_title("Figure 5. Feature Discriminability Scatter", fontsize=12)

legend = [
    mpatches.Patch(color="#c0392b", label="Tier 1 (★ ≥80% prevalence)"),
    mpatches.Patch(color="#7f8c8d", label="Tier 2/3 features"),
    mpatches.Patch(facecolor="green", alpha=0.15, label="High-utility zone (prev>50%, FP<30%)"),
]
ax.legend(handles=legend, fontsize=9, loc="lower right")
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig("fig5_discriminability_scatter.png", dpi=150, bbox_inches="tight")
print("Saved fig5_discriminability_scatter.png")
plt.show()
