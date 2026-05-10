"""
Figure 2: Mean triage score (±1 SD) per malware family and benign baseline.
Reproduces Figure 2 from the paper.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("../data/pe_features_v4.csv")

# Group: malware families + benign
groups = df["family"].unique().tolist()
order = ["Trickbot", "Emotet", "Formbook", "Lumma", "Sality", "Upatre", "Virut", "Zeus", "benign"]
order = [g for g in order if g in groups] + [g for g in groups if g not in order]

means, stds, labels = [], [], []
for g in order:
    subset = df[df["family"] == g]["triage_score"]
    means.append(subset.mean())
    stds.append(subset.std())
    labels.append(g)

colours = ["#c0392b" if l != "benign" else "#2980b9" for l in labels]

fig, ax = plt.subplots(figsize=(10, 5))
x = np.arange(len(labels))
bars = ax.bar(x, means, yerr=stds, color=colours, alpha=0.85,
              capsize=5, error_kw={"elinewidth": 1.2, "ecolor": "black"})

# Benign mean reference line
benign_mean = df[df["family"] == "benign"]["triage_score"].mean()
ax.axhline(benign_mean, color="red", linestyle="--", linewidth=1.5,
           label=f"Benign mean ({benign_mean:.1f})")

ax.set_xticks(x)
ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=10)
ax.set_ylabel("Triage Score (0–100)", fontsize=10)
ax.set_title("Figure 2. Mean Triage Score (±1 SD) per Malware Family and Benign Baseline", fontsize=11)
ax.legend(fontsize=9)
ax.set_ylim(0, 100)
ax.grid(axis="y", alpha=0.3)

plt.tight_layout()
plt.savefig("fig2_triage_score_bar.png", dpi=150, bbox_inches="tight")
print("Saved fig2_triage_score_bar.png")
plt.show()
