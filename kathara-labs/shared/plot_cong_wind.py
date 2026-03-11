#!/usr/bin/env python3

import re
import os
import matplotlib.pyplot as plt

FILE_TO_READ = os.getenv("CONG_WIN_LOG_PATH", "cong_win.csv")

timestamps = []
cong_wins = []
adv_wins = []

with open(FILE_TO_READ) as f:
    for line in f:
        m = re.match(
            r"timestamp=(\d+),\s*cong_win=(\d+),\s*send_adv_win=(\d+)", line.strip()
        )
        if not m:
            continue
        timestamps.append(int(m.group(1)))
        cong_wins.append(int(m.group(2)) / 1024)  # Convert to KB
        adv_wins.append(int(m.group(3)) / 1024)   # Convert to KB

# Convert timestamps to relative seconds from the first entry
if timestamps:
    base = timestamps[0]
    times = [(t - base) / 1000.0 for t in timestamps]
else:
    times = []

fig, ax1 = plt.subplots(figsize=(18, 6))

ax1.plot(times, cong_wins, label="Congestion Window", linewidth=3, color="tab:blue")
ax1.set_xlabel("Time (s)", fontsize=18)
ax1.set_ylabel("Congestion Window (KB)", fontsize=18, color="tab:blue")
ax1.tick_params(axis="both", labelsize=18)
ax1.tick_params(axis="y", labelcolor="tab:blue")
ax1.set_ylim(bottom=0)  # Ensure y-axis starts at 0

lines1, labels1 = ax1.get_legend_handles_labels()
ax1.legend(lines1, labels1, fontsize=16)

plt.title("Congestion Window Over Time", fontsize=24)
output_filename = os.path.splitext(os.path.basename(FILE_TO_READ))[0] + "_graph.png"
plt.savefig(output_filename, bbox_inches="tight")
plt.show()
