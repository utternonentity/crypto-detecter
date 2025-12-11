# Cryptocontainer Lab

Prototype forensic toolkit for detecting and validating cryptographic containers within court-oriented workflows.

## Project Layout
```
pyproject.toml
src/
  cryptocontainer_lab/
    core/
    detector/
    context/
    memory/
    unlock/
    recover/
    crack/
    report/
    cli/
    gui/
```

## Usage
Create a case and scan artefacts using the CLI (Python 3.11+):

```
cryptocontainer-lab case-new ./cases/demo --examiner "Analyst"
cryptocontainer-lab scan-disk --case-path ./cases/demo --image disk.dd
cryptocontainer-lab report --case-path ./cases/demo --out ./cases/demo/reports/report.json --fmt json
```

The tool is a research prototype; cryptographic validation logic is simplified and cracking functionality is intentionally unimplemented.
