import re
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="darkgrid")

files = {
    1024: "results_210.txt",
    2048: "results_211.txt",
    4096: "results_212.txt",
    8192: "results_213.txt",
    16384: "results_214.txt",
}

# (title, comp metric, verify metric, color1, color2)
plots = [
    ("open_open_proof", "open-open proof extraction", "open-open proof verification", "#0066FF", "#00E5FF"),
    ("open_open_checkpoint", "open-open checkpoint proof extraction", "open-open checkpoint verification", "#00C853", "#B2FF59"),
    ("open_close_proof", "open-close proof extraction", "open-close proof verification", "#FF6D00", "#FFD600"),
    ("open_close_checkpoint", "open-close checkpoint proof extraction", "open-close checkpoint verification", "#D50000", "#FF4081"),
    ("dne_proof", "dne proof extraction", "dne proof verification", "#AA00FF", "#EA80FC"),
    ("dne_checkpoint", "dne checkpoint proof extraction", "dne checkpoint verification", "#00BFA5", "#64FFDA"),
]


def extract_metric(filename, metric):
    pattern = re.compile(
        rf"{re.escape(metric)}:\s*mean=([\d.]+)\s*ms\s*std=([\d.]+)\s*ms"
    )
    with open(filename, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                return float(match.group(1)), float(match.group(2))
    raise ValueError(f"{metric} not found in {filename}")


def plot_and_save(title, comp_metric, verify_metric, color1, color2):
    leaves = list(files.keys())
    x = np.arange(len(leaves))
    width = 0.35

    comp_means, comp_stds = [], []
    verify_means, verify_stds = [], []

    for leaf in leaves:
        mean, std = extract_metric(files[leaf], comp_metric)
        comp_means.append(mean)
        comp_stds.append(std)

        mean, std = extract_metric(files[leaf], verify_metric)
        verify_means.append(mean)
        verify_stds.append(std)

    plt.figure(figsize=(8, 5))

    plt.bar(
        x - width / 2,
        comp_means,
        width,
        yerr=comp_stds,
        capsize=5,
        color=color1,
        edgecolor="black",
        linewidth=0.8
    )

    plt.bar(
        x + width / 2,
        verify_means,
        width,
        yerr=verify_stds,
        capsize=5,
        color=color2,
        edgecolor="black",
        linewidth=0.8
    )

    plt.xticks(x, leaves, fontweight="bold")
    plt.yticks(fontweight="bold")

    plt.xlabel("Number of Leaves", fontweight="bold")
    plt.ylabel("Time (ms)", fontweight="bold")

    plt.tight_layout()

    # Save PNG
    filename = f"{title}.png"
    plt.savefig(filename, dpi=300, bbox_inches="tight")

    plt.close()


# Generate and save all plots
for title, comp, verify, c1, c2 in plots:
    plot_and_save(title, comp, verify, c1, c2)

print("All plots saved as PNG files.")
