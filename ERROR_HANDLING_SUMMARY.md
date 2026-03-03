# Error Handling Improvements Summary

## Overview

Added comprehensive P0-level error handling to improve robustness and user experience. All changes use English and avoid emojis.

## Modified Files

### 1. `evaluation/models/llm_judge.py`

**Added OpenAI API Error Handling:**

- **AuthenticationError**: Clear message when NGC_API_KEY is invalid
- **RateLimitError**: Suggests waiting or reducing batch size with --limit
- **APIConnectionError**: Checks network, API endpoint, and firewall
- **BadRequestError**: Detects model_not_found errors and suggests valid models
- **APIError**: Catches general API errors with helpful context
- **Prompt Length Warning**: Warns when prompt exceeds ~100k characters
- **Timeout**: Added 120-second timeout to all API calls

**Example Error Messages:**
```
ERROR: Authentication failed with NGC API
Please check that NGC_API_KEY environment variable is set correctly

ERROR: NGC API rate limit exceeded
Please wait a few minutes and try again, or reduce batch size with --limit

ERROR: Model not found: invalid-model-name
Common models: meta/llama-3.1-70b-instruct, mistralai/mistral-small-3.1-24b-instruct-2503
```

---

### 2. `evaluation/api_client.py`

**Added HTTP Error Classification:**

For all API endpoints (fetch_jobs, fetch_job_by_id, fetch_traces, submit_evaluation):

- **TimeoutException**: Identifies slow servers or large payloads
- **ConnectError**: Suggests checking network, BASE_URL, and firewall
- **HTTPStatusError with specific codes:**
  - **401 Unauthorized**: Check API_TOKEN
  - **403 Forbidden**: Token lacks permissions
  - **404 Not Found**: Resource doesn't exist or wrong endpoint
  - **413 Payload Too Large**: Reduce data size
  - **429 Rate Limit**: Wait before retrying
  - **500+ Server Errors**: Service temporarily unavailable

**Added File Loading Error Handling:**

- **FileNotFoundError**: Clear message with exact path
- **json.JSONDecodeError**: Shows line/column number of error
- **PermissionError**: Identifies read permission issues
- **Auto-converts single objects to lists** for consistency

**Example Error Messages:**
```
ERROR: Authentication failed (401 Unauthorized)
Please check your API_TOKEN environment variable

ERROR: Jobs file not found: data/jobs.json
ERROR: Invalid JSON in traces file: data/traces.json
JSON error at line 45 column 12: Expecting ',' delimiter
Please check the file format
```

---

### 3. `scripts/run_cve_evaluation.py`

**Added Input Validation:**

- **Limit parameter**: Must be positive integer
- **BASE_URL format**: Must start with http:// or https://
- **Local file existence**: Checks both jobs and traces files exist
- **Submit flag warning**: Warns when --submit used in local mode
- **Output directory validation**: Creates directory if needed, handles permissions

**Example Error Messages:**
```
ERROR: --limit must be a positive integer, got: -5

ERROR: BASE_URL must start with http:// or https://
Current value: invalid-url

ERROR: Jobs file not found: test_data/missing.json
Please provide a valid path to the jobs JSON file

WARNING: --submit flag ignored in local mode
Results will only be saved locally
```

---

### 4. `evaluation/extractors/data_extractor.py`

**Added JSON Parsing Error Handling:**

Applied to 4 critical JSON parsing locations:

1. **JSON file line parsing**: Warns and skips invalid lines, continues processing
2. **CVE output parsing**: Logs warning and continues to next span
3. **Metadata parsing**: Logs warning and skips that investigation step
4. **Intel score parsing**: Logs warning and continues to next span

All JSON errors log the error message and problematic content (truncated) for debugging.

**Example Error Messages:**
```
WARNING: Invalid JSON at line 42: Expecting property name enclosed in double quotes
WARNING: Failed to parse metadata JSON for question: Is the vulnerable function reachable...
JSON error: Unterminated string starting at: line 1 column 234
```

---

## Testing Recommendations

### 1. Test API Authentication Errors

```bash
# Test with invalid token
export NGC_API_KEY="invalid-key"
python scripts/run_cve_evaluation.py --mode api --limit 1

# Expected: Clear authentication error message
```

### 2. Test Missing Files

```bash
# Test with non-existent file
python scripts/run_cve_evaluation.py --mode local \
  --jobs-file missing.json \
  --traces-file missing.json

# Expected: Clear file not found errors
```

### 3. Test Invalid JSON

```bash
# Create a file with invalid JSON
echo '{"invalid": json}' > test_invalid.json

# Run with invalid file
python scripts/run_cve_evaluation.py --mode local \
  --jobs-file test_invalid.json \
  --traces-file test_invalid.json

# Expected: JSON parsing error with line/column info
```

### 4. Test Rate Limiting

```bash
# Run with large limit to potentially hit rate limits
python scripts/run_cve_evaluation.py --mode api --limit 100

# Expected: If rate limited, clear message suggesting to wait
```

### 5. Test Invalid Parameters

```bash
# Test negative limit
python scripts/run_cve_evaluation.py --mode api --limit -5

# Expected: Parameter validation error

# Test invalid BASE_URL
export BASE="not-a-url"
python scripts/run_cve_evaluation.py --mode api

# Expected: URL format validation error
```

---

## Error Handling Coverage

| Error Type | Coverage | Status |
|------------|----------|--------|
| **OpenAI API Errors** | Authentication, Rate Limit, Connection, Bad Request | ✅ Complete |
| **HTTP Errors** | 401, 403, 404, 413, 429, 500+ | ✅ Complete |
| **Network Errors** | Timeout, Connection failure | ✅ Complete |
| **File Errors** | Not found, Invalid JSON, Permission denied | ✅ Complete |
| **Input Validation** | Parameters, URLs, file paths | ✅ Complete |
| **JSON Parsing** | Malformed JSON in all critical paths | ✅ Complete |

---

## What Was NOT Added (P1/P2 - Future Work)

### P1 - Could Add Later:
- Retry mechanism with exponential backoff (requires `tenacity` library)
- Network connectivity pre-check
- CVE ID format validation
- Component/version validation

### P2 - Nice to Have:
- Token count estimation and truncation
- Model response format validation
- Comprehensive input sanitization
- Progress bars for long operations

---

## Migration Notes

**No Breaking Changes**: All error handling is additive and backward compatible.

**Log Level**: All error messages use appropriate logging levels:
- `logger.error()` for critical errors that stop execution
- `logger.warning()` for recoverable issues that skip items
- `logger.debug()` for detailed debugging information

**Dependencies**: No new dependencies required. All error handling uses Python standard library and existing dependencies (httpx, openai).

---

## Next Steps

1. **Test the changes** with the commands above
2. **Run existing tests** to ensure no regressions:
   ```bash
   cd /Users/heatherzhang/Documents/GitHub/cve_evaluation_toolkit
   python scripts/test_data_parser.py
   ```

3. **Try local mode** with your existing test data:
   ```bash
   python scripts/run_cve_evaluation.py --mode local \
     --jobs-file src/evaluation/test_data/jobs_integration_test_all.json \
     --traces-file src/evaluation/test_data/traces_integration_test_all.json \
     --no-submit --limit 1
   ```

4. **Test API mode** (when API is available):
   ```bash
   export BASE="https://your-api.com"
   export TOKEN="your-token"
   export NGC_API_KEY="your-ngc-key"
   python scripts/run_cve_evaluation.py --mode api --limit 1 --no-submit
   ```

---

## Summary

Added comprehensive error handling that:
- ✅ Provides clear, actionable error messages
- ✅ Distinguishes between different failure types
- ✅ Helps users diagnose and fix issues quickly
- ✅ Prevents crashes from common edge cases
- ✅ Uses plain English without emojis
- ✅ Maintains backward compatibility
- ✅ Passes all linter checks
