# Challenge 2 - Automatic Discovery of Vulnerabilities in GitHub CI/CD Workflows & Their Patches

## Overview

This project aims to automatically detect command injection vulnerabilities in GitHub Actions workflows and generate patches that eliminate those vulnerabilities.

The project consists of two tasks:

1. **Task 1 – Vulnerability Detection**
    - Detect vulnerable data flows.
    - Report only the **first exploitable sink** for each tainted flow.

2. **Task 2 – Patch Generation**
    - Generate a git-compatible patch that fixes **the entire tainted flow**, not just the first reported sink.

---

# Challenge Requirements

The model should:

- Analyze GitHub Actions workflows
- Resolve referenced Actions
- Resolve reusable workflows
- Track tainted data across files
- Detect vulnerable shell execution
- Generate patches
- Produce outputs in the competition format

Final submission should contain:

```
submission.pdf
README.md
test.csv
patches/
```

where

```
patches/
    sample_001.patch
    sample_002.patch
    ...
```

---

# Dataset Structure

```
train/

    workflows/

    actions/

    reusable_workflows/

    patches/

validation/

    workflows/

    actions/

    reusable_workflows/
```

---

# Important Challenge Rules

## Detection

For each taint flow:

✔ Report ONLY the first exploitable sink.

Example

```
Issue title
      ↓
echo "${{ github.event.issue.title }}"
      ↓
msg.txt
      ↓
bash -c "$TITLE"
```

Only report

```
github.event.issue.title
```

NOT

```
msg.txt
```

---

If two independent sources exist

```
github.event.issue.title

github.event.pull_request.title
```

both must be reported independently.

---

## Patch

Unlike detection,

Patch generation must fix **every vulnerable use** of the tainted value.

Example

```
Issue Title
     ↓
echo
     ↓
file
     ↓
eval
```

Even though detection reports only the first sink,

the patch must eliminate both vulnerable usages.

---

# Overall Architecture

```
Workflow YAML
        │
        ▼
YAML Parser
        │
        ▼
Workflow Graph Builder
        │
        ▼
Reference Resolver
        │
        ▼
Interprocedural Taint Analysis
        │
        ▼
Sink Detection
        │
        ▼
Patch Generator
        │
        ▼
Unified Diff Generator
        │
        ▼
test.csv + patches/
```

---

# Phase 1 — Understand GitHub Actions

## Learn

- GitHub Actions syntax
- Jobs
- Steps
- uses
- run
- Composite actions
- Reusable workflows
- Environment variables
- GitHub contexts

Resources

GitHub Actions Documentation

https://docs.github.com/actions

GitHub Contexts

https://docs.github.com/actions/learn-github-actions/contexts

Expressions

https://docs.github.com/actions/learn-github-actions/expressions

---

# Phase 2 — Study the Dataset

Understand

train.csv

Contains

- sample_id
- vulnerabilities
- patches

Understand

untrusted_data.csv

Contains all tainted GitHub contexts.

No need to detect additional source types outside this list.

---

# Phase 3 — Build YAML Parser

Recommended

Python

Libraries

```
PyYAML

ruamel.yaml
```

Need to parse

```
jobs

steps

run

uses

env

with
```

---

# Phase 4 — Reference Resolution

Need to resolve

## Actions

```
uses: owner/repo@sha
```

↓

```
actions/

owner/

repo/

sha/

action.yml
```

---

Reusable workflows

```
uses:

owner/repo/.github/workflows/test.yml@sha
```

↓

```
reusable_workflows/

owner/

repo/

sha/

.github/workflows/test.yml
```

---

Need recursive loading.

---

# Phase 5 — Build Internal Representation

Convert workflow into a graph.

Each node represents

- run step
- action
- reusable workflow

Edges represent execution order.

Need line numbers for reporting.

---

# Phase 6 — Taint Analysis

This is the core of the project.

Track

```
GitHub Context

↓

Expression

↓

Environment Variable

↓

Output

↓

File

↓

Another Workflow

↓

Shell Command
```

Need

- propagation
- alias tracking
- environment propagation
- output propagation

---

# Phase 7 — Detect Vulnerabilities

Sources

Read from

```
untrusted_data.csv
```

Sinks

Examples

```
run:

bash

sh

python

node

pwsh

cmd

powershell
```

Need to determine

Does tainted data reach shell execution?

If yes

Record only first sink.

---

# Phase 8 — Patch Generation

Patch strategy

Prefer

Move tainted values into environment variables.

Example

Instead of

```
run:

echo "${{ github.event.issue.title }}"
```

Generate

```
env:

TITLE:

${{ github.event.issue.title }}

run:

printf '%s\n' "$TITLE"
```

Avoid

- eval
- bash -c
- unquoted interpolation

Need git-compatible unified diff.

---

# Phase 9 — Output Generation

Generate

```
test.csv
```

Fields

```
sample_id

vulnerabilities

patches
```

Generate

```
patches/

sample.patch
```

---

# Suggested Project Structure

```
project/

│

├── parser/

│       yaml_parser.py

│

├── resolver/

│       actions.py

│       reusable.py

│

├── taint/

│       tracker.py

│       propagation.py

│

├── detector/

│       detector.py

│       sinks.py

│

├── patch/

│       generator.py

│       diff.py

│

├── utils/

│

├── main.py

│

└── README.md
```

---

# Technologies

Language

- Python 3.11+

Libraries

```
PyYAML

networkx

pandas

difflib

pathlib

json

re
```

Optional

```
tree-sitter

CodeQL

Semgrep

```

---

# Learning Resources

GitHub Actions

https://docs.github.com/actions

YAML

https://yaml.org/

Git Unified Diff

https://git-scm.com/docs/diff-format

Python difflib

https://docs.python.org/3/library/difflib.html

Semgrep Taint Analysis

https://semgrep.dev/docs/writing-rules/data-flow/taint-mode

CodeQL Data Flow

https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/

---

# Milestones

## Week 1

- Read challenge
- Explore dataset
- Study GitHub Actions
- Implement YAML parser

---

## Week 2

- Implement reference resolution
- Build workflow graph
- Implement taint tracking

---

## Week 3

- Detect vulnerabilities
- Validate on training samples
- Improve precision

---

## Week 4

- Generate patches
- Produce unified diffs
- Generate test.csv
- Prepare submission

---

# Success Criteria

Detection

- Correctly identify vulnerable workflows.
- Report only the first sink for each taint flow.
- Avoid false positives on safe workflows.

Patching

- Eliminate the entire tainted flow.
- Produce valid git apply-compatible patches.
- Preserve workflow functionality whenever possible.

Submission

- All required files are generated.
- Patches apply cleanly.
- Output matches the expected competition format.