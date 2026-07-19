import re
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from pathlib import Path
from common_paths import RESULT_DIR

# Try multiple possible paths
possible_paths = [
    RESULT_DIR / "base" / "stack_pivot_vs_arc_real.log",
]
log_path = None
for p in possible_paths:
    if Path(p).exists():
        log_path = p
        break
if log_path is None:
    raise FileNotFoundError(f"Log file not found; tried: {possible_paths}")

# Parse the log
data = {}
current_case = None
with open(log_path, 'r', encoding='utf-8') as fh:
    for line in fh:
        m = re.search(r"\bSTART\s+(\S+)", line)
        if m:
            current_case = m.group(1).strip()
            continue
        m2 = re.search(r"gadget chain length\s*:\s*(\d+)\s*time\s*:\s*([0-9.]+)", line)
        if m2 and current_case:
            length = int(m2.group(1))
            t = float(m2.group(2))
            data.setdefault(current_case, []).append({'length': length, 'time': t})

if not data:
    print('No data parsed. Check the log path and format. Tried path:', log_path)
rows = {}
binaries = set()
behaviors = set()
for case, entries in data.items():
    if '/' in case:
        binary = case.split('/')[0]
        rest = case.split('/')[1]
    else:
        binary = case
        rest = case
    behavior = rest.split('-')[-1]
    binaries.add(binary)
    behaviors.add(behavior)
    lengths = [e['length'] for e in entries]
    times = [e['time'] for e in entries]
    mean_len = int(round(sum(lengths)/len(lengths)))
    mean_time = sum(times)/len(times)
    rows.setdefault(behavior, {})[binary] = f"{mean_len}/{mean_time:.3f}"

binaries = sorted(binaries)
behaviors = sorted(behaviors)

df = pd.DataFrame(index=behaviors, columns=binaries)
for beh, d in rows.items():
    for bin_, val in d.items():
        df.at[beh, bin_] = val

df_display = df.fillna('')
df_t = df_display.T

import math
time_df = pd.DataFrame(index=behaviors, columns=binaries, dtype=float)
for beh in behaviors:
    for bin_ in binaries:
        v = rows.get(beh, {}).get(bin_)
        time_df.at[beh, bin_] = float(v.split('/')[1]) if v is not None else math.nan
time_df_t = time_df.T

# Controllable Reg | Tools | binaries...
# rax | DynOP | ...
#     | ARCANIST | ... (leave empty for now)
regs = ['rax', 'rdi', 'rdx', 'rsi']
tools = ['DynOP', 'ARCANIST']

rows_formatted = []
for reg in regs:
    for tool in tools:
        row = {'Controllable Reg': reg, 'Tools': tool}
        for bin_ in binaries:
            if tool == 'DynOP':
                # Read values from the previously computed rows (behavior -> {binary: 'len/time'})
                val = rows.get(reg, {}).get(bin_)
                row[bin_] = val if val is not None else ''
            else:
                # Keep ARCANIST empty for now
                row[bin_] = ''
        rows_formatted.append(row)

df_format = pd.DataFrame(rows_formatted, columns=['Controllable Reg', 'Tools'] + binaries)
print(df_format)
