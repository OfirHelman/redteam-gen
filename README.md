# Red Team Attack Generator

An LLM-driven tool that generates realistic process-command attack datasets on demand.

## What it does
- Generates ~220 process commands per scenario
- Exactly 20 malicious commands woven into ~200 benign background noise
- Plants benign twins (same tools, innocent paths) to trap defenders
- Scatters malicious commands so no 3+ appear in a row
- Outputs CSV + ground truth + attack story

## Usage
```bash
source venv/bin/activate
streamlit run app.py
```

Type a scenario (ransomware, lateral movement, etc.) and click Generate.

## Requirements
- Python 3.10+
- Azure OpenAI API key in `.env`