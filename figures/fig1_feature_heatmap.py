"""
Figure 1: Tier 1 Feature × Family Heatmap with FP% column.
Reproduces Figure 1 from the paper.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib.patches import Patch

# ── Data from Table 1 ─────────────────────────────────────────────────────────
features = [
    "PE checksum zero",
    "RWX section flag",
    "No ASLR/DEP",
    "Anti-analysis imports",
    "Unpacking imports",
    "Dynamic API strings",
    "Dynamic resolution flag",
    "Network/C2 strings",
    "High entropy section",
    "Hardcoded file paths",
    "Crypto-related strings",
    "Base64 blobs",
    "Overlay data",
]

families = ["Trickbot", "Emotet", "Formbook", "Lumma", "Sality", "Upatre", "Virut", "Zeus"]

# Visibility rates (%) — rows=features, cols=families
data = np.array([
    [47, 58, 67, 35, 100, 51, 100, 58],
    [ 0,  0,  0,  0, 100, 15,  74, 21],
    [51, 42,  3,  0,  80, 69,  95, 79],
    [58, 96, 83, 92,  90, 72,  69, 66],
    [63, 98, 81, 62,  58, 69,  44, 55],
    [74, 98, 83, 85,  84, 67,  82, 89],
    [58, 96, 78, 65,  72, 44,  51, 53],
    [67, 84, 94,100,  78, 28,  67, 61],
    [51, 31, 89, 35,  82, 41,  64, 61],
    [79, 49, 81, 92,  56, 31,  44, 55],
    [28, 27, 11, 85,  24,  5,  36, 11],
    [95, 38, 86, 73,  48, 46,  62, 50],
    [47, 16,  8, 12,  54, 82,  36, 61],
], dtype=float)

fp_rates = [0, 0, 0, 83, 74, 74, 26, 26, 7, 46, 7, 57, 98]

# ── Plot ──────────────────────────────────────────────────────────────────────
fig, (ax_main, ax_fp) = plt.subplots(
    1, 2, figsize=(14, 6),
    gridspec_kw={"width_ratios": [8, 1], "wspace": 0.04}
)

# Main heatmap
cmap_main = plt.cm.YlOrRd
im = ax_main.imshow(data, cmap=cmap_main, vmin=0, vmax=100, aspect="auto")

# Annotate cells
for i in range(len(features)):
    for j in range(len(families)):
        val = data[i, j]
        is_tier1 = val >= 80
        text = f"{val:.0f}"
        colour = "white" if val > 60 else "black"
        weight = "bold" if is_tier1 else "normal"
        marker = "*" if is_tier1 else ""
        ax_main.text(j, i, f"{text}{marker}", ha="center", va="center",
                     fontsize=8, color=colour, fontweight=weight)

ax_main.set_xticks(range(len(families)))
ax_main.set_xticklabels(families, rotation=30, ha="right", fontsize=9)
ax_main.set_yticks(range(len(features)))
ax_main.set_yticklabels(features, fontsize=9)
ax_main.set_title("Tier 1 Feature Prevalence (%) Across Malware Families", fontsize=11, pad=10)

plt.colorbar(im, ax=ax_main, fraction=0.03, pad=0.02, label="Visibility rate (%)")

# FP% column
fp_cmap = mcolors.LinearSegmentedColormap.from_list("fp", ["#2ecc71", "#e74c3c"])
fp_data = np.array(fp_rates).reshape(-1, 1)
ax_fp.imshow(fp_data, cmap=fp_cmap, vmin=0, vmax=100, aspect="auto")
for i, fp in enumerate(fp_rates):
    colour = "white" if fp > 50 else "black"
    ax_fp.text(0, i, f"{fp}%", ha="center", va="center", fontsize=8, color=colour)

ax_fp.set_xticks([0])
ax_fp.set_xticklabels(["FP%"], fontsize=9)
ax_fp.set_yticks([])
ax_fp.set_title("FP%", fontsize=9, pad=10)

legend_elements = [
    Patch(facecolor="#d62728", label="Tier 1 (≥80%, * marked)"),
    Patch(facecolor="#ff7f0e", label="Supporting (50–79%)"),
    Patch(facecolor="#ffffcc", edgecolor="grey", label="Weak (<50%)"),
]
ax_main.legend(handles=legend_elements, loc="lower right", fontsize=8, framealpha=0.9)

fig.suptitle(
    "Figure 1. Heatmap of static forensic feature prevalence across eight malware families\n"
    "(n=316) and benign baseline (n=46). * = Tier 1 (≥80%). FP% = false-positive rate in benign set.",
    fontsize=9, y=0.01, ha="center"
)

plt.tight_layout(rect=[0, 0.05, 1, 1])
plt.savefig("fig1_feature_heatmap.png", dpi=150, bbox_inches="tight")
print("Saved fig1_feature_heatmap.png")
plt.show()
