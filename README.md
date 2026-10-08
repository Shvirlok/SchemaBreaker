# ⚡ SchemaBreaker

**Automated Stress-Testing & Adversarial Fuzzing for LLM Structured Outputs (Pydantic & JSON Schema)**

SchemaBreaker probes and fuzz-tests your Pydantic data models and system prompts against adversarial edge cases before you ship them to production. It exposes subtle validation crashes, enum violations, markdown code fence leaks, type confusion traps, prompt injection vulnerabilities, and latency spikes across Google Gemini models (`gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-1.5-flash`, etc.).

---

## 🚀 Key Features

- **Adversarial Fuzzing Engine**: Synthesizes multi-vector attack scenarios using a dedicated Red-Teamer LLM agent and heuristic structural schema introspection.
- **Async Concurrency & Telemetry**: Evaluates dozens of edge-case scenarios in parallel with real-time throughput, latency ($P_{50}, P_{95}, P_{99}$), and TTFT tracking.
- **Pydantic v2 Deep Validation**: Intercepts exact field-level validation errors, enum mismatches, missing required keys, and markdown fence leaks (` ```json ... ``` `).
- **Composite Schema Health Score (0-100)**: Calculates an integrity grade (A+, A, B, C, D, F) weighting pass rate, failure severity, latency resilience, and injection resistance.
- **Actionable Remediation Engine**: Automatically drafts syntax-highlighted Pydantic code patches (flexible before-validators, fallback enums) and system prompt hardening directives.
- **Cyberpunk Terminal UI**: Sleek, dark-mode terminal dashboard with ASCII branding, live progress bars, KPI summary cards, and failure inspectors.
- **Interactive Reports & Dashboard**: Export full telemetry to JSON, GitHub-flavored Markdown for CI/CD, or standalone interactive HTML dashboards. Includes a built-in Streamlit web micro-app (`schemabreaker web`).

---

## 🛡️ Attack Vectors Tested

| Attack Vector | Focus & Edge Cases Tested |
| :--- | :--- |
| **Prompt Injection & Jailbreak** | Delimiter escapes, system override tags (`[SYSTEM]`), instructions to bypass schema constraints |
| **Enum & Allowed Values** | Ambiguous multi-intent queries, unsupported states, casing variations, colloquial slang |
| **Type Confusion & Coercion** | Numbers spelled as English words ("one thousand"), comma-separated strings for lists, stringified booleans |
| **Boundary & Payload Stress** | Negative quantities, zero divisors, extreme floats, 10,000-char string floods, empty lists |
| **Unicode & Control Chars** | Zalgo glitch text, Right-to-Left (RTL) overrides, zero-width spaces (`\u200b`), 4-byte UTF-8 emoji storms |
| **Null & Missing Keys** | Explicit null requests on non-nullable fields, omitted required keys, empty payload bodies |
| **Contradictory Instructions** | Contradictory states (e.g., complete, cancel, and refund simultaneously) |
| **Schema Hallucination** | Decoy attributes tempting the model to invent unapproved keys |
| **Syntactic Malformation** | Forced markdown code fence wrappers (` ```json ... ``` `), unclosed quotes |

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/your-org/SchemaBreaker.git
cd SchemaBreaker

# Install package
pip install -e .
```

---

## ⚡ Quick Start

### 1. Instant 1-Command Demo

Run an adversarial audit on the pre-packaged E-Commerce Transaction Parser schema:

```bash
schemabreaker demo
```

To export an interactive HTML dashboard:
```bash
schemabreaker demo --export-html report.html
```

### 2. Audit Your Own Pydantic Model

```bash
# Audit a specific model from a Python file
schemabreaker run -s my_app/models.py -m OrderPayload -n 25 -c 5

# Audit a JSON Schema
schemabreaker run -s schemas/user_profile.json -n 20
```

### 3. Launch Standalone Web Application (Cyberpunk UI)

SchemaBreaker includes a developer-first, dark cyberpunk single-page web app powered by FastAPI + Tailwind CSS:

```bash
# Launch on http://localhost:8501
python3 -m schemabreaker.web

# Or via CLI
schemabreaker web --port 8501

# Or directly with Uvicorn
uvicorn web.app:app --reload --port 8501
```

Features:
- **Two-Column Layout**: Left configuration pane with Monaco-style schema & system prompt editors, preset switchers, vector checkboxes, and sliders; Right pane with real-time audit streaming.
- **SSE Real-time Streaming (`/api/audit/stream`)**: Watch test cases execute live with animated pulse indicators and status chips.
- **Interactive Failure Accordion**: Deep inspection of adversarial inputs, malformed LLM outputs, and Pydantic validation trace diffs.
- **1-Click Remediation & Patches**: Automated regex sanitizers, Pydantic v2 `@field_validator(mode='before')` hooks, and prompt hardening directives.
- **Download Reports**: Export JSON telemetry and standalone interactive HTML files directly from the browser.

---

## 🛠️ CLI Reference

```
Usage: schemabreaker [OPTIONS] COMMAND [ARGS]...

Commands:
  run          Run adversarial stress-test audit on a schema.
  audit        Alias for 'run'.
  demo         Launch instant out-of-the-box demo audit.
  web          Launch the interactive Streamlit web dashboard.
  list-demos   List built-in demonstration schemas.
```

### Options for `schemabreaker run`

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `--schema` | `-s` | `ecommerce` | Path to `.py` file, `.json` schema, or demo name (`ecommerce`, `clinical`, `financial`) |
| `--model-name` | `-m` | `None` | Pydantic class name inside the file (auto-detected if omitted) |
| `--system-prompt` | `-p` | `None` | Inline system prompt string |
| `--prompt-file` | | `None` | Path to text file containing system prompt |
| `--tests` | `-n` | `20` | Number of adversarial fuzz test runs |
| `--concurrency` | `-c` | `5` | Number of concurrent async workers |
| `--target-model` | | `gemini-2.5-flash` | Target Gemini model to stress-test |
| `--generator-model` | | `gemini-2.5-flash` | LLM model for Red Teamer generator |
| `--temperature` | | `0.2` | Sampling temperature for target model |
| `--mock` | | `False` | Run in offline mock simulation mode |
| `--vector` | `-v` | `None` | Filter by specific attack vector (can be specified multiple times) |
| `--export-json` | | `None` | File path to save JSON audit report |
| `--export-html` | | `None` | File path to save standalone interactive HTML report |
| `--export-md` | | `None` | File path to save GitHub-flavored Markdown report |

---

## 🧩 Pre-Packaged Demo Schemas

SchemaBreaker includes realistic target schemas ready for stress-testing:

1. **`ecommerce` (`CustomerOrder`)**:
   - Nested order items with SKU regex constraints (`^[A-Z0-9]{3,4}-[A-Z0-9]{3,4}-[A-Z0-9]{2,4}$`).
   - ISO currency enums (`USD`, `EUR`, `GBP`, `CAD`, `JPY`), tax rates, delivery coordinates, and payment validation.
2. **`clinical` (`ClinicalAssessment`)**:
   - Patient vitals ranges (heart rate, blood pressure, temperature, SpO2).
   - Triage levels (`RESUSCITATION`, `EMERGENT`, `URGENT`), medications dosage, and ICD-10 diagnostic codes.
3. **`financial` (`LoanApplication`)**:
   - Debt-to-income (DTI) ratio bounds, FICO credit scores (300-850), and underwriting risk tier classifications.

---

## 📊 Health Score Formula

The Composite Health Score is computed as:

$$\text{Health Score} = 100 \times \Big( 0.40 \cdot \text{PassRate} + 0.25 \cdot \text{SeverityScore} + 0.20 \cdot \text{LatencyScore} + 0.15 \cdot \text{SecurityScore} \Big)$$

- **Pass Rate (40%)**: Ratio of valid outputs to total test cases.
- **Severity Score (25%)**: Penalizes syntax crashes and unhandled leaks over soft validation errors.
- **Latency Score (20%)**: Evaluates tail latency ratio ($P_{95} / P_{50}$) and spike resistance.
- **Security Score (15%)**: Resilience against prompt injections and jailbreaks.

---

## 🧪 Running Tests

```bash
python -m pytest -v
```

---

## 📄 License

Apache 2.0. Built for developers building production-grade LLM applications with Gemini and Pydantic.
