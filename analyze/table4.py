import re
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from pathlib import Path
from common_paths import RESULT_DIR

# 尝试多种可能路径
possible_paths = [
    RESULT_DIR / "base" / "stack_pivot_vs_arc_real.log",
]
log_path = None
for p in possible_paths:
    if Path(p).exists():
        log_path = p
        break
if log_path is None:
    raise FileNotFoundError(f"找不到日志文件，尝试过: {possible_paths}")

# 解析日志
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
    print('未解析到任何数据（请检查日志路径与格式），已尝试路径：', log_path)
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
#     | ARCANIST | ... (先空着)
regs = ['rax', 'rdi', 'rdx', 'rsi']
tools = ['DynOP', 'ARCANIST']

rows_formatted = []
for reg in regs:
    for tool in tools:
        row = {'Controllable Reg': reg, 'Tools': tool}
        for bin_ in binaries:
            if tool == 'DynOP':
                # 从之前计算的 rows (behavior -> {binary: 'len/time'}) 中取值
                val = rows.get(reg, {}).get(bin_)
                row[bin_] = val if val is not None else ''
            else:
                # ARCANIST 先保持为空
                row[bin_] = ''
        rows_formatted.append(row)

df_format = pd.DataFrame(rows_formatted, columns=['Controllable Reg', 'Tools'] + binaries)
print(df_format)
