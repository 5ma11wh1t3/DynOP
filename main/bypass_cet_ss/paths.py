from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"
RESULTS_DIR = REPO_ROOT / "results"

BENCHMARK_CONTEXT_DIR = DATASET_DIR / "benchmark" / "benchmark_context_info"
BENCHMARK_GADGET_DIR = DATASET_DIR / "benchmark" / "benchmark_gadget"
CFI_DIR = DATASET_DIR / "CFI"
