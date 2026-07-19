from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"
RESULT_DIR = REPO_ROOT / "result"

BENCHMARK_BINARY_DIR = DATASET_DIR / "benchmark" / "benchmark_binary"
BENCHMARK_CONTEXT_DIR = DATASET_DIR / "benchmark" / "benchmark_context_info"
BENCHMARK_GADGET_DIR = DATASET_DIR / "benchmark" / "benchmark_gadget"

WITHOUT_VCM_RESULT_DIR = RESULT_DIR / "without_vcm"
