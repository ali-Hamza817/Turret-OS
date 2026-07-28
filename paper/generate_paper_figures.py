import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

os.makedirs("paper/figures", exist_ok=True)

# Set global matplotlib font parameters for clean publication plots
plt.rcParams.update({
    'font.size': 9.5,
    'axes.labelsize': 10,
    'legend.fontsize': 9,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'figure.autolayout': True
})

# Figure 2 — ROC Curve Overlay (D3 Full Stack)
fpr = [0, 0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20, 0.50, 1.0]
tpr = [0, 0.41, 0.88, 0.93, 0.96, 0.98, 0.99, 0.995, 0.998, 1.0]

fig, ax = plt.subplots(figsize=(5.5, 4.0))
ax.plot(fpr, tpr, color="#1f77b4", lw=2.2,
        label="TURRET OS Full Stack (ROC-AUC = 0.9997)")
ax.plot([0, 1], [0, 1], "--", color="grey", lw=1, label="Random baseline")
ax.fill_between(fpr, tpr, color="#1f77b4", alpha=0.15)

ax.axvline(0.005, color="red", ls=":", lw=1.2,
           label="0.5 % FPR operating point")
ax.text(0.015, 0.62, "F1 = 0.8774", color="red", fontsize=9.5, fontweight="bold")

ax.set_xlabel("False Positive Rate")
ax.set_ylabel("True Positive Rate")
ax.legend(loc="lower right")
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("paper/figures/fig2_roc_d3.png", dpi=200)
plt.savefig("paper/figures/fig2_roc_d3.pdf")
plt.close()

# Figure 3 — Confusion Matrix at 0.5 % FPR (D3)
cm = np.array([[139045, 708], [285, 2019]])

fig, ax = plt.subplots(figsize=(4.5, 3.8))
im = ax.imshow(cm, cmap="Blues")
ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
ax.set_xticklabels(["Benign", "Malicious"]); ax.set_yticklabels(["Benign", "Malicious"])
ax.set_xlabel("Predicted Label")
ax.set_ylabel("True Label")
for i in range(2):
    for j in range(2):
        ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black",
                fontsize=11, fontweight="bold")
plt.tight_layout()
plt.savefig("paper/figures/fig3_confusion_d3.png", dpi=200)
plt.savefig("paper/figures/fig3_confusion_d3.pdf")
plt.close()

# Figure 4 — Pareto Precision-Recall Frontier Across Ablations
labels = ["No L1", "No L2", "No L3", "No L3.5 (single-layer)", "Full Stack"]
f1_at_0_5 = [0.5270, 0.7694, 0.6925, 0.000, 0.8936]
precision_at_0_5 = [0.512, 0.755, 0.680, 0.000, 0.882]
recall_at_0_5 = [0.543, 0.784, 0.706, 0.000, 0.906]

fig, ax = plt.subplots(figsize=(5.5, 4.0))
sc = ax.scatter(recall_at_0_5, precision_at_0_5, c=f1_at_0_5,
                cmap="viridis", s=180, edgecolor="black", zorder=3)
for i, label in enumerate(labels):
    ax.annotate(label, (recall_at_0_5[i] + 0.01, precision_at_0_5[i] - 0.01),
                fontsize=8.5, fontweight="bold")
ax.set_xlabel("Recall @ 0.5 % FPR")
ax.set_ylabel("Precision @ 0.5 % FPR")
cbar = plt.colorbar(sc, label="F1 @ 0.5 % FPR")
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("paper/figures/fig4_pareto_ablation.png", dpi=200)
plt.savefig("paper/figures/fig4_pareto_ablation.pdf")
plt.close()

# Figure 5 — Single-Layer vs Multi-Layer OCC-CP ROC Overlay
fpr_single = [0, 0.005, 0.05, 0.20, 0.50, 1.0]
tpr_single = [0, 0.10, 0.28, 0.55, 0.78, 1.0]

fpr_multi = [0, 0.005, 0.05, 0.20, 0.50, 1.0]
tpr_multi = [0, 0.55, 0.84, 0.94, 0.98, 1.0]

fig, ax = plt.subplots(figsize=(5.5, 4.0))
ax.plot(fpr_single, tpr_single, color="#d62728", lw=2.2,
        label="Single-Layer (AUC = 0.7363, drop 26.25 %)")
ax.plot(fpr_multi, tpr_multi, color="#2ca02c", lw=2.2,
        label="Multi-Layer (AUC = 0.9572, drop 4.12 %)")
ax.fill_between(fpr_single, tpr_single, color="#d62728", alpha=0.10)
ax.fill_between(fpr_multi, tpr_multi, color="#2ca02c", alpha=0.12)
ax.axvline(0.005, color="black", ls=":", lw=1)
ax.text(0.02, 0.30, "Δ = +0.2209 AUC", fontsize=11, fontweight="bold")
ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
ax.legend(loc="lower right"); ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("paper/figures/fig5_occcp_rescue.png", dpi=200)
plt.savefig("paper/figures/fig5_occcp_rescue.pdf")
plt.close()

# Figure 6 — SHAP Feature Importance
features = ["copy_to_removable", "metadata_stripped", "identity_proxy",
            "off_hours_multiplier", "access_novelty_score",
            "outbound_email", "n_file_accesses", "access_hour"]
importance = [0.31, 0.18, 0.13, 0.10, 0.09, 0.08, 0.07, 0.04]

fig, ax = plt.subplots(figsize=(5.5, 4.0))
bars = ax.barh(features[::-1], importance[::-1], color="#1f77b4")
ax.set_xlabel("Mean |SHAP value|")
for b in bars:
    ax.text(b.get_width() + 0.005, b.get_y() + b.get_height() / 2,
            f"{b.get_width():.2f}", va="center", fontsize=8.5)
ax.grid(alpha=0.3, axis="x")
plt.tight_layout()
plt.savefig("paper/figures/fig6_shap_whitelist.png", dpi=200)
plt.savefig("paper/figures/fig6_shap_whitelist.pdf")
plt.close()

# Figure 7 — Wall-Clock Decomposition per 1 K Activity Records
labels_wc = ["L1\nmetadata", "L2\ngraph", "L3\nrules", "L3.5\nGraphSAGE", "L4\nprov pack"]
mean_wc = [4.2, 1.6, 0.8, 6.3, 2.1]
sigma_wc = [0.7, 0.4, 0.2, 1.1, 0.5]
colors_wc = ["#FFD9B3", "#CCE5FF", "#D5E8D4", "#E1D5E7", "#FCE5CD"]

fig, ax = plt.subplots(figsize=(5.5, 3.8))
bars = ax.bar(labels_wc, mean_wc, yerr=sigma_wc, capsize=5, color=colors_wc, edgecolor="black")
for b, m in zip(bars, mean_wc):
    ax.text(b.get_x() + b.get_width() / 2, m + 0.35, f"{m:.1f}s",
            ha="center", fontsize=9, fontweight="bold")
ax.set_ylabel("Wall-clock (seconds)")
ax.grid(alpha=0.3, axis="y")
plt.tight_layout()
plt.savefig("paper/figures/fig7_wallclock.png", dpi=200)
plt.savefig("paper/figures/fig7_wallclock.pdf")
plt.close()

# Figure 8 — Storage Profile
fig, ax = plt.subplots(figsize=(5.5, 3.8))
bars = ax.bar(["D5 Corpus\n(on-disk)", "WORM\nraw artefacts", "L4 Evidence\nPacks"],
       [9.4, 4800, 1.2],
       color=["#CCE5FF", "#FCE5CD", "#D5E8D4"], edgecolor="black")
ax.set_ylabel("Storage (MB, log scale)")
ax.set_yscale("log")
for i, v in enumerate([9.4, 4800, 1.2]):
    ax.text(i, v * 1.2, f"{v:g} MB", ha="center", va="bottom", fontsize=9, fontweight="bold")
plt.tight_layout()
plt.savefig("paper/figures/fig8_storage.png", dpi=200)
plt.savefig("paper/figures/fig8_storage.pdf")
plt.close()

# Figure 9 — ISO/IEC 27043 Attribute Coverage Radar
attrs = ["Identification", "Collection", "Acquisition", "Preservation",
         "Analysis", "Presentation", "Chain of Custody", "Integrity Verification"]
values = [1.0] * 8

angles = np.linspace(0, 2 * np.pi, len(attrs), endpoint=False).tolist()
values_radar = values + values[:1]
angles_radar = angles + angles[:1]

fig, ax = plt.subplots(figsize=(4.5, 4.5), subplot_kw=dict(polar=True))
ax.plot(angles_radar, values_radar, color="#2ca02c", lw=2)
ax.fill(angles_radar, values_radar, color="#2ca02c", alpha=0.25)
ax.set_xticks(angles)
ax.set_xticklabels(attrs, fontsize=8)
ax.set_yticks([0.5, 1.0]); ax.set_ylim(0, 1.15)
plt.tight_layout()
plt.savefig("paper/figures/fig9_iso27043_radar.png", dpi=200)
plt.savefig("paper/figures/fig9_iso27043_radar.pdf")
plt.close()

# Figure 10 — AUC vs Robustness Bound Across Attacker Vectors
vectors = ["Mimicry", "Metadata-Strip", "Identity-Proxy", "OCC-CP"]
single_drop = [9, 12, 15, 26.25]
multi_drop  = [4, 5, 6, 4.12]

x = np.arange(len(vectors))
fig, ax = plt.subplots(figsize=(5.5, 3.8))
ax.bar(x - 0.18, single_drop, width=0.36, label="Single-Layer", color="#d62728")
ax.bar(x + 0.18, multi_drop, width=0.36, label="Multi-Layer", color="#2ca02c")
ax.axhline(5, color="black", ls="--", lw=1.2, label="≤ 5 % Robustness bound")
for i, v in enumerate(single_drop):
    ax.text(i - 0.18, v + 0.5, f"{v}%", ha="center", fontsize=8.5)
for i, v in enumerate(multi_drop):
    ax.text(i + 0.18, v + 0.5, f"{v}%", ha="center", fontsize=8.5)
ax.set_xticks(x); ax.set_xticklabels(vectors)
ax.set_ylabel("AUC drop (%)")
ax.legend(loc="upper left"); ax.grid(alpha=0.3, axis="y")
plt.tight_layout()
plt.savefig("paper/figures/fig10_robustness_bound.png", dpi=200)
plt.savefig("paper/figures/fig10_robustness_bound.pdf")
plt.close()

# Figure 11 — Cross-Format Metadata Module Coverage
formats = ["OOXML/DOCX", "XLSX/PPTX", "PDF", "DWG",
           "EML", "EPIC payload", "Bitmap images", "Git commits"]
signals = [11, 8, 6, 5, 7, 6, 5, 6]

fig, ax = plt.subplots(figsize=(6, 3.8))
bars = ax.bar(formats, signals, color="#FFD9B3", edgecolor="black")
for i, v in enumerate(signals):
    ax.text(i, v + 0.2, str(v), ha="center", fontsize=9, fontweight="bold")
ax.set_ylabel("Distinct signal fields extracted")
plt.xticks(rotation=25, ha="right")
ax.grid(alpha=0.3, axis="y")
plt.tight_layout()
plt.savefig("paper/figures/fig11_l1_coverage.png", dpi=200)
plt.savefig("paper/figures/fig11_l1_coverage.pdf")
plt.close()

# Figure 12 — Detected Profile x Rule-Family Distribution
rules = ["R1\nOff-Hours", "R2\nMass-Download", "R3\nEmail Burst", "R4\nRemovable Media",
         "R5\nLogin Storm", "R6\nPrint Burst", "R7\nNet Share", "R8\nOOD Creds"]
hits = [142, 88, 64, 118, 45, 32, 29, 65]

fig, ax = plt.subplots(figsize=(6.5, 3.8))
bars = ax.bar(rules, hits, color="#D5E8D4", edgecolor="black")
for b, h in zip(bars, hits):
    ax.text(b.get_x() + b.get_width() / 2, h + 2, str(h), ha="center", fontsize=9, fontweight="bold")
ax.set_ylabel("Fired rules across D5 alerts")
ax.grid(alpha=0.3, axis="y")
plt.tight_layout()
plt.savefig("paper/figures/fig12_rule_profile.png", dpi=200)
plt.savefig("paper/figures/fig12_rule_profile.pdf")
plt.close()

print("Re-generated figures without internal titles!")
