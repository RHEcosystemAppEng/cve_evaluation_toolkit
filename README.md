# CVE Evaluation Toolkit

A comprehensive automated evaluation framework for assessing the quality of CVE (Common Vulnerabilities and Exposures) analysis pipelines using LLM-as-a-Judge methodology.

## Overview

This toolkit evaluates CVE analysis outputs across multiple dimensions:
- **Checklist Generation**: Evaluates the relevance and quality of investigation checklists
- **Investigation Process**: Assesses agent reasoning, tool selection, and answer quality
- **Summary Quality**: Evaluates conciseness and completeness of vulnerability summaries
- **Justification**: Validates vulnerability classification decisions
- **Intel Score**: Verifies accuracy of CVSS-like risk scoring

## Features

### Multi-Stage Evaluation

#### Stage 1: Intel Score (`CALCULATE_CVE_SCORE`)
- **SCORE_FIDELITY** (0.8 threshold): Accuracy of CVSS-like scoring breakdown

#### Stage 2: Checklist Generation (`CHECKLIST_GENERATION`)
Evaluates the quality of generated investigation checklists:
- **CHECKLIST_PROMPT_ALIGNMENT** (0.7 threshold): Measures how well the checklist aligns with CVE description
- **CHECKLIST_QUALITY** (0.7 threshold): Assesses relevance, completeness, actionability, and prioritization

#### Stage 3: Investigation (`AGENT_LOOP`)
Evaluates the agent's investigation process for each checklist question:
- **AGENT_LOOP_ANSWER_QUALITY** (0.7 threshold): Relevancy and evidence support
- **AGENT_LOOP_REASONING_QUALITY** (0.7 threshold): Logical coherence and goal focus
- **AGENT_LOOP_TOOL_SELECTION_QUALITY** (0.7 threshold): Appropriateness and sequence of tool usage
- **AGENT_LOOP_TOOL_CALL_INTEGRITY** (0.7 threshold): Syntactic correctness of tool calls

#### Stage 4: Summary (`SUMMARIZE`)
- **SUMMARY_QUALITY** (0.7 threshold): Conciseness and coverage of key findings

#### Stage 5: Justification (`JUSTIFICATION`)
- **JUSTIFICATION_QUALITY** (0.7 threshold): Evidence support and logical soundness


### Flexible Execution Modes

- **API Mode**: Fetch jobs from remote cluster, evaluate, and submit results
- **Local Mode**: Test with local JSON files
- **Dry Run**: Generate reports without submitting to API
- **Selective Evaluation**: Run specific stages only

### Output Formats

- **Local Format**: Nested JSON with detailed breakdowns
- **API Format**: Flat list of metrics ready for submission

## Installation

### Prerequisites

- Python 3.12+
- `uv` package manager (recommended) or `pip`

### Using uv (Recommended)

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone repository
git clone <repository-url>
cd cve_evaluation_toolkit

# Create virtual environment and install dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows
```

### Using pip

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configuration

### Environment Variables

Create a `.env` file or export the following:

```bash
# Required for API mode
export BASE="https://your-api-endpoint.com"
export TOKEN="your-token"

# Required for LLM Judge
export NGC_API_KEY="your-nvidia-api-key"

# Optional: Override default model
export JUDGE_MODEL="meta/llama-3.1-70b-instruct"
export JUDGE_BASE_URL="https://integrate.api.nvidia.com/v1"
```

## Usage

### Default: Evaluate All Stages

```bash
# Evaluate latest integration test batch (all stages, auto-submit)
python3 scripts/run_cve_evaluation.py \
  --mode api \
  --limit 5 \
  --submit
```

### Evaluate Specific Job and Stages

```bash
# Only investigation metrics for a specific job
python3 scripts/run_cve_evaluation.py \
  --mode api \
  --job-id abc123-def456 \
  --stages investigation \
  --no-submit \
  --output investigation_results.json
```

### Local Testing with Files

```bash
# Test with local JSON files
python3 scripts/run_cve_evaluation.py \
  --mode local \
  --jobs-file tests/test_data/jobs_integration_test_all.json \
  --traces-file tests/test_data/api_traces_all.json \
  --no-submit \
  --output local_test.json
```

### Command-Line Arguments

```
Required:
  --mode {api,local}        Execution mode

API Mode Options:
  --batch-type TYPE         Batch type filter (default: INTEGRATION_TESTS)
  --language LANG           Language filter (default: all)
  --limit N                 Max jobs to process (default: 10)
  --job-id ID               Evaluate single job only

Local Mode Options:
  --jobs-file PATH          Path to jobs JSON file
  --traces-file PATH        Path to traces JSON file

Evaluation Options:
  --stages STAGE [STAGE ...]
                            Stages to evaluate (default: all)
                            Options: all, checklist, investigation,
                                     summary, justification, intel_score

Output Options:
  --submit                  Submit results to API (default)
  --no-submit               Skip API submission
  --output FILE             Output file path (default: test_results.json)
  --output-format {local,api}
                            Output format (default: local)
```

## Data Flow

```
1. FETCH JOBS
   API: /api/v1/batch/latest?batch_type=INTEGRATION_TESTS
   → List of CVE analysis jobs

2. FETCH TRACES (per job)
   API: /api/v1/traces/all?jobId={job_id}
   → OpenTelemetry spans with LLM execution details

3. PARSE DATA
   APIExtractor.extract_from_job(job, traces)
   → CVEAnalysisResult object

4. EVALUATE
   Run metric suites on parsed data
   → Evaluation results with scores and reasoning

5. FORMAT
   Convert to API format (if --output-format api)
   → Flat list of metrics

6. SUBMIT (if --submit)
   POST /api/v1/evals
   → Store results in ML-OPS database
```

## API Schema

### Evaluation Result Format

Each evaluation metric is submitted with for example:

```json
{
  "job_id": "string",
  "trace_id": "string",
  "execution_start_timestamp": "2025-02-19T10:30:00Z",
  "cve": "CVE-2024-1234",
  "component": "string",
  "component_version": "string",
  "llm_node": "AGENT_LOOP",
  "metric_name": "AGENT_LOOP_ANSWER_QUALITY",
  "metric_score": "0.85",
  "metric_reasoning": "The answer directly addresses...",
  "model_input": "Is the vulnerable function used?",
  "model_output": "Yes, the function is called in...",
}
```

### Valid llm_node Values
- `CALCULATE_CVE_SCORE`
- `CHECKLIST_GENERATION`
- `AGENT_LOOP`
- `SUMMARIZE`
- `JUSTIFICATION`

### Valid metric_name Values
See [Features](#features) section for complete list.

## Testing and Development

### Preview Parsed Data

```bash
# Test data extraction without running evaluation
python3 scripts/test_data_parser.py

# Outputs:
# - Console: Formatted preview of parsed data
# - File: parsed_data_preview.json
```

## Metrics and Scoring

### Score Interpretation

- **0.9-1.0**: Excellent - Production ready
- **0.7-0.8**: Good - Minor improvements needed
- **0.5-0.6**: Adequate - Significant improvements required
- **0.3-0.4**: Poor - Major issues detected
- **0.0-0.2**: Fail - Critical problems

### Passing Criteria

Each metric has a threshold (typically 0.7). A job "passes" a stage when all metrics in that stage exceed their thresholds.

### Aggregation

- **Stage Score**: Average of all metrics in that stage
- **Overall Score**: Weighted average across all stages

## Troubleshooting

### Common Issues

#### 401 Unauthorized
```bash
# Token expired, regenerate:
export TOKEN=$(oc create token...)
```

#### 404 Not Found (NVIDIA API)
```bash
# Check model name and base URL:
export JUDGE_MODEL="meta/llama-3.1-70b-instruct"
export JUDGE_BASE_URL="https://integrate.api.nvidia.com/v1"
```

#### No traces found for job
- The job may still be running
- Check job status in ML-OPS UI
- Try with `--limit 1` to test single completed job

#### Module import errors
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
uv sync --force
```

## Contributing

### Code Style

```bash
# Format code
black evaluation/ scripts/

# Lint
ruff check evaluation/ scripts/

# Type check
mypy evaluation/
```

### Adding New Metrics

1. Create metric function in `evaluation/metrics/agent/<stage>_metrics.py`
2. Add to corresponding `MetricSuite` class
3. Update `run_cve_evaluation.py` to include in evaluation flow
4. Update this README with metric description

## License

Apache-2.0 License. See [LICENSE](LICENSE) for details.

## Support

For issues and questions:
- Internal: Contact the CVE Analysis Team
- GitHub: Open an issue in this repository

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
