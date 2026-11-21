# AGY Guardian (Benchmark Prototype)

Local `PreToolUse` command approval classifier prototype for evaluating **open-weight Decision Models** (`llama-server` native `POST /v1/systemone`, zero output tokens) head-to-head against single-token generative LLM baselines (`POST /v1/chat/completions` with GBNF grammar).

## Prerequisites

- Python 3.12+ (pure standard library — zero runtime dependencies)
- `llama-server` built with native Decision Model (`/v1/systemone`) support (`llama.cpp` Oct 2026+ / PR #29818)

## Local Setup

1. Copy `.env.example` to `.env` (gitignored) and set your local paths:
   - `AGY_GUARDIAN_LLAMA_SERVER` (optional explicit path to your CUDA/Vulkan `llama-server` binary; leave empty to use `PATH`)
   - `AGY_GUARDIAN_DECISION_MODELS_DIR` and `AGY_GUARDIAN_LLM_MODELS_DIR`
2. Copy `bench/models.example.json` to `.local/models.json` (gitignored) and adjust the list of models you want to benchmark.

Settings precedence: `CLI flags > OS env vars > .env > code defaults`.

## Running the Benchmark

```powershell
# Run all models configured in .env / .local/models.json
python bench/run_bench.py

# Filter to a single model and compare single-question vs. multi-question SystemOne schemas
python bench/run_bench.py --model clef-flash --schema both
```

Reports and per-case JSONL outputs are written to `.local/benchmark_results/` (gitignored).
