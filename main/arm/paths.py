from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"
RESULT_DIR = REPO_ROOT / "result"

ARM_DATASET_DIR = DATASET_DIR / "arm_dataset"
ARM_CVE_DIR = DATASET_DIR / "arm_cves"
