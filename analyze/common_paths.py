from pathlib import Path
import sys


ANALYZE_DIR = Path(__file__).resolve().parent
REPO_ROOT = ANALYZE_DIR.parent
MAIN_DIR = REPO_ROOT / "main"
MAIN_BASE_X86_DIR = MAIN_DIR / "base_x86"
DATASET_DIR = REPO_ROOT / "dataset"
RESULT_DIR = REPO_ROOT / "result"
RESULTS_DIR = REPO_ROOT / "results"
SOTA_RESULT_DIR = RESULT_DIR / "sota"


def add_base_x86_to_syspath():
    base_x86 = str(MAIN_BASE_X86_DIR)
    if base_x86 not in sys.path:
        sys.path.insert(0, base_x86)
