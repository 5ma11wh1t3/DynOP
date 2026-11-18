<div align="center">

# DynOP

### Blow Away the Cobwebs in NX Bypassing with Dynamic-Source Gadget Oriented Programming

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.kernel.org/)
[![Arch](https://img.shields.io/badge/Arch-x86__64%20|%20ARM-red)](.)
[![License](https://img.shields.io/badge/License-Research-green)](.)

*An automated gadget chain synthesis framework for constrained memory-control scenarios*

English

</div>

---

## Table of Contents

- [Overview](#1-overview)
- [Key Ideas](#2-key-ideas)
- [Repository Layout](#3-repository-layout)
- [Environment](#4-environment)
- [Quick Start](#5-quick-start)
- [Experiments](#6-experiments)
- [Running Sub-Scripts](#7-running-sub-scripts)
- [Result Directories](#8-result-directories)
- [Analysis & Plotting](#9-analysis--plotting)
- [Baselines](#10-baselines)
- [Path Overrides](#11-path-overrides)
- [Extending to Other Targets](#12-extending-to-other-targets)

---

## 1. Overview

**DynOP** is an automated gadget-chain synthesis framework for constrained memory-control scenarios. It targets cases where traditional ROP/JOP/COP tools are hard to apply, and aims to automatically construct executable exploit chains even when large contiguous controllable stack regions are unavailable. Instead of relying only on stack-resident payload layouts, DynOP leverages **Dynamic-Source Gadgets**, combining runtime register states, context-dependent memory values, **VCM (Virtual Controllable Memory)**, context-aware filtering, and backward constraint propagation to control the search space and synthesize valid chains.

The repository is consolidated around `main/`. The recommended entry point is:

```bash
python3 main/run_experiment.py <experiment> [options]
```

## 2. Key Ideas

| Technique | Description |
|:----------|:------------|
| **Dynamic-Source Gadget** | Gadgets are not treated only as sequences of return addresses on the stack; key inputs may come from registers or runtime-reachable memory |
| **VCM** | Decouples logical constraint solving from the physical payload layout, addressing the allocation paradox |
| **Backward Constraint Propagation** | Propagates gadget semantic constraints backward to reduce meaningless search |
| **Context-Aware Filtering** | Prunes the gadget dependency graph according to the hijack-time context |

Workflow:

> 1️⃣ Normalize gadget semantics → 2️⃣ Context-based reachability & dependency filtering → 3️⃣ Build state transitions & register dependencies → 4️⃣ Solver synthesizes final chain & memory layout

## 3. Repository Layout

```
DynOP/
├── main/                   # 🔑 Consolidated experiment code (recommended entry)
│   ├── run_experiment.py   #    Unified experiment entry
│   ├── base_x86/           #    x86 baseline (CVE / benchmark / stack pivot)
│   ├── without_vcm/        #    DynOP-w/o VCM benchmark
│   ├── bypass_cet_ss/      #    CET-SS benchmark & demo
│   ├── bypass_cet_ibt/     #    CET-IBT demo
│   └── arm/                #    ARM benchmark & CVE
├── dataset/                # 📦 Experiment input data
├── result/                 # 📊 Main experiment outputs (x86 / ARM / w/o VCM / SOTA)
├── results/                # 📊 CET-related experiment outputs
├── sota/                   # 🔬 Baseline tools
│   ├── arcanist/
│   ├── cracker/
│   ├── ropbot/
│   └── sgc/
└── analyze/                # 📈 Paper figure/table analysis scripts
```

## 4. Environment

```bash
# Core dependencies
pip install triton keystone-engine pwntools loguru capstone pyelftools
```

| Dependency | Purpose | Note |
|:-----------|:--------|:-----|
| `triton-library` | Symbolic execution engine | Core |
| `keystone-engine` | Assembler | Core |
| `pwntools` | Exploit toolkit | Core |
| `loguru` | Logging | Core |
| `capstone` | Disassembler | Core |
| `pyelftools` | ELF parsing | Core |
| `ROPgadget` | Gadget extraction | Auto-invoked when gadget file is missing |
| Docker / angr / Rust | Baseline reproduction | Only needed by some `sota/` scripts |

> ⚠️ `sota/arcanist` requires a **commercial Binary Ninja license**; the repository only keeps the modified scripts needed for the experiments.

## 5. Quick Start

```bash
# Show help
python3 main/run_experiment.py --help

# Minimal reproduction: run all main experiments
python3 main/run_experiment.py dynop-cve
python3 main/run_experiment.py dynop-benchmark
python3 main/run_experiment.py dynop-real-pivot
python3 main/run_experiment.py dynop-without-vcm
python3 main/run_experiment.py cet-none
python3 main/run_experiment.py cet-ss-benchmark
python3 main/run_experiment.py cet-ss-demo
python3 main/run_experiment.py cet-ibt-demo
python3 main/run_experiment.py cet-ss-ibt-demo
python3 main/run_experiment.py arm-benchmark
python3 main/run_experiment.py arm-cve
```

Supported experiments at a glance:

| Experiment | Description | Default Output |
|:-----------|:------------|:---------------|
| `dynop-cve` | x86 CVE validation | `result/base/cve/<target>/` |
| `dynop-benchmark` | x86 benchmark | `result/base/benchmark/<target>/` |
| `dynop-real-pivot` | Real binary stack pivot | `result/base/stack_pivot_vs_arc_real.log` |
| `dynop-without-vcm` | Ablation (no VCM) | `result/without_vcm/benchmark/<target>/` |
| `cet-none` | No-CET baseline (libxul) | `results/cet_none/` |
| `cet-ss-benchmark` | CET-SS benchmark | `results/cop_benchmark_v2/` |
| `cet-ss-demo` | CET-SS demo | — |
| `cet-ibt-demo` | CET-IBT demo | — |
| `cet-ss-ibt-demo` | CET-SS + IBT demo | — |
| `arm-benchmark` | ARM benchmark | `result/<arch>/<target>/results.json` |
| `arm-cve` | ARM CVE validation | `result/arm/cve_cases/` |

---

## 6. Experiments

<details>
<summary><b>6.1 DynOP CVE</b></summary>

```bash
python3 main/run_experiment.py dynop-cve
```

Arguments:
- `--target {funcall4,execve}` — default `funcall4`
- `--case <name>` — run a single CVE case (default: `Fortigate-42475`)
- `--cve-dataset-dir <path>` / `--result-dir <path>`

Built-in x86 CVE cases: `Bento4` · `Fortigate-42475` · `ffmpeg-10191` · `Fortigate-25610` · `Fortigate-21762` · `Synacktiv PR4100` · `Serv-U` · `Fortigate-23113` · `ffmpeg-10190`

```bash
# Examples
python3 main/run_experiment.py dynop-cve --case "Synacktiv PR4100"
python3 main/run_experiment.py dynop-cve --target execve --case "Fortigate-42475"
```

</details>

<details>
<summary><b>6.2 DynOP Benchmark</b></summary>

```bash
python3 main/run_experiment.py dynop-benchmark
```

Arguments:
- `--target {funcall4,execve}` · `--system <system>` · `--binary <name>` (without `.bin`)
- `--benchmark-binary-dir` / `--benchmark-context-dir` / `--benchmark-gadget-dir` / `--result-dir`

Supported systems: `centos-7.1810` · `debian-10-cloud` · `openbsd-62` · `openbsd-64` · `openbsd-65` · `gcc_fzero` · `openbsd-73`

```bash
# Examples
python3 main/run_experiment.py dynop-benchmark --system centos-7.1810
python3 main/run_experiment.py dynop-benchmark --system centos-7.1810 --binary btrfs-map-logical
```

</details>

<details>
<summary><b>6.3 DynOP Real Binary Stack Pivot</b></summary>

```bash
python3 main/run_experiment.py dynop-real-pivot
```

Arguments:
- `--binary <path>` — e.g. `Nginx/nginx` (relative to `real_binary/`)
- `--case <reg>` — default set: `rax`, `rdi`, `rsi`, `rdx`
- `--real-dataset-dir <path>` / `--result-log <path>`

> If `dataset/real-linux-software/real_binary/<binary>.txt` does not exist, the script will invoke `ROPgadget` to generate it.

```bash
# Examples
python3 main/run_experiment.py dynop-real-pivot --binary Nginx/nginx --case rax
python3 main/run_experiment.py dynop-real-pivot --binary Firefox/libxul.so --case rdi
```

</details>

<details>
<summary><b>6.4 DynOP-w/o VCM</b></summary>

```bash
python3 main/run_experiment.py dynop-without-vcm
```

Arguments are mostly the same as `dynop-benchmark`: `--target` · `--system` · `--binary` · `--benchmark-*-dir` · `--result-dir`

```bash
# Example
python3 main/run_experiment.py dynop-without-vcm --system centos-7.1810 --binary btrfs-map-logical
```

</details>

<details>
<summary><b>6.5 CET-None (No CET Baseline)</b></summary>

```bash
python3 main/run_experiment.py cet-none
```

Uses the base DynOP solver (ROP with ret) on `dataset/CFI/libxul_none`, serving as the no-CET baseline for comparison with CET-SS/IBT experiments.

Arguments:
- `--target {funcall4,execve}` — default `funcall4`
- `--dataset` (default `dataset/CFI/libxul_none`) · `--gadget-file`
- `--search-depth` (default `3`) · `--timeout` (default `600`)
- `--result-dir` (default `results/cet_none/`)

</details>

<details>
<summary><b>6.6 CET-SS Benchmark</b></summary>

```bash
python3 main/run_experiment.py cet-ss-benchmark
```

Arguments:
- `--threads <n>` (default `8`) · `--timeout <sec>` (default `300`)
- `--system <system>` · `--binary <name>` (without `.bin`)
- `--info-dir` / `--gadget-dir` / `--output`

```bash
# Example
python3 main/run_experiment.py cet-ss-benchmark --system centos-7.1810 --binary auvirt
```

</details>

<details>
<summary><b>6.7 CET-SS Demo</b></summary>

```bash
python3 main/run_experiment.py cet-ss-demo
```

Arguments: `--dataset` (default `dataset/CFI/libxul_ss`) · `--gadget-file` · `--threads` (default `8`)

Default goal: construct a function call with `rdi = 0x400040`, `rsi = 0x1000`, `rdx = 7`

</details>

<details>
<summary><b>6.8 CET-IBT Demo</b></summary>

```bash
python3 main/run_experiment.py cet-ibt-demo
```

Arguments: `--dataset` (default `dataset/CFI/libxul_ibt`) · `--gadget-file` · `--cyclic-file` · `--binary-file` · `--search-depth` (default `3`) · `--timeout` (default `600`)

</details>

<details>
<summary><b>6.9 CET-SS + IBT Demo</b></summary>

```bash
python3 main/run_experiment.py cet-ss-ibt-demo
```

Arguments: `--dataset` (default `dataset/CFI/libxul_full`) · `--gadget-file` · `--threads` (default `1`)

</details>

<details>
<summary><b>6.10 ARM Benchmark</b></summary>

```bash
python3 main/run_experiment.py arm-benchmark
```

Arguments:
- `--arch {x86_64,arm,armel,mips,mipsel}` (default `arm`) · `--target {funcall4,execve}`
- `--dataset` (default `dataset/arm_dataset`) · `--gadget-dir` · `--context-dir`
- `--max-binaries` (default `1000`) · `--workers` (default `32`) · `--binary` · `--result-dir` · `--skip-done`

```bash
# Examples
python3 main/run_experiment.py arm-benchmark --binary ion_libbss.so.0.0.0
python3 main/run_experiment.py arm-benchmark --workers 16 --max-binaries 200
```

</details>

<details>
<summary><b>6.11 ARM CVE</b></summary>

```bash
python3 main/run_experiment.py arm-cve
```

Arguments: `--case <name>` · `--dataset-base` (default `dataset/arm_cves`) · `--result-dir` (default `result/arm/cve_cases`)

Built-in cases: `CVE-2019-1010298` · `CVE-2022-46152` · `CVE-2023-30799_arm`

</details>

---

## 7. Running Sub-Scripts

Although the unified entry is recommended, sub-scripts under `main/` can still be executed directly:

```bash
python3 main/base_x86/cve_log.py --case "Synacktiv PR4100"
python3 main/base_x86/benchmark_log.py --system centos-7.1810 --binary btrfs-map-logical
python3 main/base_x86/run_libxul_none.py
python3 main/bypass_cet_ss/run_benchmark_cop_v2.py --system centos-7.1810 --binary auvirt
python3 main/bypass_cet_ss/run_libxul_ss_v2.py
python3 main/bypass_cet_ibt/run_libxul_ibt.py
python3 main/arm/run_parallel.py --arch arm --binary ion_libbss.so.0.0.0
python3 main/arm/test_cves.py CVE-2019-1010298
```

## 8. Result Directories

| Path | Content |
|:-----|:--------|
| `result/base/...` | x86 DynOP baseline experiments |
| `result/without_vcm/...` | DynOP-w/o VCM |
| `result/arm/...` | ARM benchmark & ARM CVE |
| `result/sota/...` | Baseline comparison results |
| `results/cet_none/...` | CET-None baseline |
| `results/cop_benchmark_v2/...` | CET-SS benchmark |

## 9. Analysis & Plotting

Scripts in `analyze/` generate paper figures and tables:

| Script | Output |
|:-------|:-------|
| `figure6-7.py` | Figure 6 / Figure 7 |
| `table2.py` | CVE experiment table summary |
| `table3.py` | DynOP vs multiple SOTA baselines |
| `table4.py` | Real-binary stack-pivot result summary |
| `table5.py` | DynOP vs w/o VCM |
| `table6.py` | AG/PG pruning statistics |
| generate_arm_benchmark.py | arm_benchmark |
| generate_cet_ss_benchmark.py | cet_ss_benchmark |
| generate_runtime_vs_chain_length.py | runtime_vs_chain_length |
| generate_runtime_vs_search_space.py | runtime_vs_search_space |

## 10. Baselines

`sota/` contains wrappers for baseline tools: `arcanist` · `cracker` · `ropbot` · `sgc`

> ⚠️ `sota/` is not part of the unified `main/` entry system. Treat baselines as separate wrapped projects.

## 11. Path Overrides

The consolidated version exposes most important paths as CLI arguments. Common override patterns:

<details>
<summary>Override benchmark paths</summary>

```bash
python3 main/run_experiment.py dynop-benchmark \
  --system centos-7.1810 \
  --binary btrfs-map-logical \
  --benchmark-binary-dir /path/to/benchmark_binary \
  --benchmark-context-dir /path/to/benchmark_context_info \
  --benchmark-gadget-dir /path/to/benchmark_gadget \
  --result-dir /path/to/output
```

</details>

<details>
<summary>Override CET-IBT demo paths</summary>

```bash
python3 main/run_experiment.py cet-ibt-demo \
  --dataset /path/to/libxul_ibt \
  --gadget-file /path/to/gadget_test.txt \
  --cyclic-file /path/to/cyclic_matches.json \
  --binary-file /path/to/libxul_ibt.so
```

</details>

<details>
<summary>Override ARM benchmark paths</summary>

```bash
python3 main/run_experiment.py arm-benchmark \
  --dataset /path/to/arm_dataset \
  --gadget-dir /path/to/gadgets \
  --context-dir /path/to/context_info \
  --result-dir /path/to/result
```

</details>

## 12. Extending to Other Targets

- **Standalone binary without program context**: Manually prepare simulated `controllable_regs.txt`, `cyclic_matches.json`, `mappings.txt`, and `registers.txt` following the format of existing cases, then run the corresponding scripts.
- **Real vulnerability research**: Replace variable-time content in the exploit with a cyclic-generated string, then use `dataset/tools/gdb_script.py` to automatically collect the program context at the control-flow hijack point, and run the corresponding scripts.
