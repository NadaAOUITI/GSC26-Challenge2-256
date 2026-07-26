# GSC 2026 — Challenge 02: GitHub Actions Vulnerability Detection

IEEE Global Student Challenge — detect code-injection flaws in GitHub Actions workflows and generate secure patches.

## Problem

GitHub Actions workflows can be vulnerable when **untrusted inputs** (branch names, PR titles, issue text, etc.) are interpolated directly into `run:` shell commands. Attackers can inject arbitrary shell code.

This project loads competition samples, scans workflow YAML for risky patterns, and will later generate patches for Kaggle submission.

## Data setup

1. Clone the competition dataset (do not commit this folder):

   ```bash
   git clone https://github.com/XinyuZhangXvX/detect-and-fix-vulnerabilities-in-github-actions.git dataset
   ```

2. Download from [Kaggle Data tab](https://www.kaggle.com/competitions/detect-and-fix-vulnerabilities-in-github-actions/data) into `data/`:
   - `train.csv` — sample IDs and ground-truth labels
   - `untrusted_data.csv` — list of untrusted GitHub context expressions

## Project layout

```text
GSC2/
  data/           # CSV metadata from Kaggle
  dataset/        # Cloned competition repo (gitignored)
  src/
    data_loader.py
    detector.py
    evaluate.py
    patcher.py
    predict.py
    main.py
  tests/
  docs/adr/
  requirements.txt
```

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt

# Scan first 10 training samples
python -m src.main scan

# Inspect one known vulnerable sample
python -m src.main scan --sample-id 63dd948580aa29a6fd4868f5

# Evaluate all 150 training samples (metrics summary)
python -m src.main eval --full
```

## Testing

```bash
pytest                          # unit + integration (integration skips without dataset)
python -m src.main eval --full  # print TP/FP/FN/recall on full train set
```

## Patch generation and predict

```bash
# Generate patch diff for one sample
python -m src.main patch --sample-id 63dd948580aa29a6fd4868f5

# Write submission CSV for train split (150 rows)
python -m src.main predict --split train --output output/submission_train.csv

# After downloading validation workflows to dataset/validation/workflows/
python -m src.main predict --split validation --output output/submission.csv
```

## Current approach

**Baseline rule-based detector** with taint tracking:

- Load samples from `train.csv`
- Read matching workflow YAML from `dataset/train/workflows/{sample_id}.yml`
- Flag direct untrusted `${{ ... }}` and propagated taint (`env.*`, `inputs.*`, `steps.*.outputs.*`) inside `run:` blocks
- Walk steps in order; follow `uses:` into composite actions and reusable workflows
- Train baseline after Feature 2: **TP=22, FP=0, FN=7** (recall ~76%)

Next steps: patch generation, optional OpenRouter LLM assist, Kaggle submission pipeline.

## Submission access

Grant **read access** to GitHub user `XinyuZhangXvX` on this team repository so Challenge 02 submissions can be reviewed.

## Team

Global Student Challenge 2026 — Challenge 02 progress check-in.
