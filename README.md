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
    main.py
  requirements.txt
```

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt

# Scan first 10 training samples
python -m src.main

# Inspect one known vulnerable sample
python -m src.main --sample-id 63dd948580aa29a6fd4868f5
```

## Current approach

**Baseline rule-based detector** (work in progress):

- Load samples from `train.csv`
- Read matching workflow YAML from `dataset/train/workflows/{sample_id}.yml`
- Flag `${{ ... }}` expressions inside `run:` blocks when they match untrusted contexts
- Follow `uses:` references into local composite actions and reusable workflows

Next steps: improve line-level accuracy, generate unified diff patches, optional OpenRouter LLM assist.

## Submission access

Grant **read access** to GitHub user `XinyuZhangXvX` on this team repository so Challenge 02 submissions can be reviewed.

## Team

Global Student Challenge 2026 — Challenge 02 progress check-in.
