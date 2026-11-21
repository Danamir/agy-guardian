# AGY Guardian (Benchmark Prototype)

Local `PreToolUse` command approval classifier prototype for evaluating **open-weight Decision Models** (`llama-server` native `POST /v1/systemone`, zero output tokens) head-to-head against single-token generative LLM baselines (`POST /completion` with GBNF grammar).

## Prerequisites

- Python 3.12+ (pure standard library — zero runtime dependencies)
- `llama-server` built with native Decision Model (`/v1/systemone`) support (`llama.cpp` Oct 2026+ / PR #29818)
- Local GGUF models configured in a manifest (copy `bench/models.example.json` to `.local/models.json`)

## Running the Benchmark

```powershell
# Run all models listed in .local/models.json
python bench/run_bench.py --manifest .local/models.json

# Filter to a single model and compare single-question vs. multi-question SystemOne schemas
python bench/run_bench.py --manifest .local/models.json --model clef-flash --schema both
```

Reports and per-case JSONL outputs are written to `.local/benchmark_results/` (gitignored).
