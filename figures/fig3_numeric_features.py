"""
Figure 3: Mean numeric forensic features across families.
(A) File entropy  (B) Packing score  (C) Import count
Reproduces Figure 3 from the paper.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("../data/pe_features_v4.csv")

order = ["Trickbot", "Emotet", "Formbook", "Lumma", "Sality", "Upatre", "Virut", "Zeus", "benign"]
order = [g for g in order if g in df["family"].unique()]

features = [
    ("file_entropy",   "Mean File Entropy (bits/byte)", "A"),
    ("packing_score",  "Mean Packing Score (0–10)",      "B"),
    ("import_count",   "Mean Import Count",              "C"),
]

fig, axes = plt.subplots(1, 3, figsize=(15, 5), sharey=False)

for ax, (col, ylabel, panel) in zip(axes, features):
    means = [df[df["family"] == g][col].mean() for g in order]
    colours = ["#c0392b" if g != "benign" else "#2980b9" for g in order]
    ax.bar(order, means, color=colours, alpha=0.85)
    ax.set_title(f"({panel}) {ylabel}", fontsize=10)
    ax.set_xticklabels(order, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.grid(axis="y", alpha=0.3)

fig.suptitle(
    "Figure 3. Mean numeric forensic features across families.\n"
    "Red = malware families; Blue = benign baseline.",
    fontsize=10, y=1.01
)
plt.tight_layout()
plt.savefig("fig3_numeric_features.png", dpi=150, bbox_inches="tight")
print("Saved fig3_numeric_features.png")
plt.show()
