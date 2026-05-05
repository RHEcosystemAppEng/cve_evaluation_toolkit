# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
API Client for exploit-iq-client ML-OPS endpoints.

Handles fetching analysis jobs and traces, and submitting evaluation results.
"""

import os
import json
from typing import Any
from typing import Optional

import httpx
from pydantic import BaseModel
from pydantic import Field
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from evaluation.utils.logger import get_logger
logger = get_logger(__name__)


class APIConfig(BaseModel):
    """Configuration for API client."""

    base_url: str = Field(default_factory=lambda: os.getenv("BASE") or os.getenv("EXPLOIT_IQ_API_BASE", ""))
    token: Optional[str] = Field(default_factory=lambda: os.getenv("TOKEN") or os.getenv("EXPLOIT_IQ_API_TOKEN"))
    timeout: int = Field(default=60, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=False, description="Whether to verify SSL certificates")

class ExploitIQClient:
    """
    Client for exploit-iq-client ML-OPS API.

    Provides methods to:
    - Fetch completed jobs
    - Fetch traces for jobs
    - Submit evaluation results
    """

    def __init__(self, config: Optional[APIConfig] = None):
        """
        Initialize API client.

        Args:
            config: Optional API configuration. Defaults to environment variables.
        """
        self.config = config or APIConfig()
        self.base_url = self.config.base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None
        logger.info("Initialized ExploitIQClient with base_url: %s", self.base_url)
    
    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create persistent async client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
        return self._client
    
    async def close(self):
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        reraise=True
    )
    async def fetch_jobs(self, status: Optional[str] = "completed", limit: Optional[int] = None, batch_id: Optional[str] = None) -> list[dict[str, Any]]:
        """
        Fetch jobs from the API with automatic retry on timeout/connection errors.

        Args:
            status: Filter by job status (default: "completed")
            limit: Maximum number of jobs to fetch
            batch_id: FILTER by specific batch_id (optional)

        Returns:
            List of job dictionaries
        """
        url = f"{self.base_url}/api/v1/jobs/all"
        params = {}
        if status:
            params["status"] = status
        if limit:
            params["limit"] = limit
        if batch_id:
            params["batch_id"] = batch_id
            logger.info("Fetching jobs from batch_id=%s from %s", batch_id, url)
        else:
            logger.info("Fetching jobs with status=%s from %s", status or "all", url)

        # async with httpx.AsyncClient(timeout=self.config.timeout, verify=self.config.verify_ssl) as client:
        try:
            response = await self.client.get(url, params=params, headers=self._get_headers())
            response.raise_for_status()
            jobs = response.json()
            logger.info("Fetched %d jobs", len(jobs) if isinstance(jobs, list) else 1)
            return jobs if isinstance(jobs, list) else [jobs]
        except httpx.TimeoutException:
            logger.error("Request timed out after %ds - server may be overloaded or unreachable", self.config.timeout)
            raise
        except httpx.ConnectError as e:
            logger.error("Connection failed - check network, BASE_URL, and firewall: %s", str(e))
            raise
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            if status_code == 401:
                logger.error("Authentication failed (401) - check API_TOKEN")
            elif status_code == 403:
                logger.error("Access forbidden (403) - insufficient permissions")
            elif status_code == 404:
                logger.error("API endpoint not found (404) - verify BASE_URL")
            elif status_code == 429:
                logger.error("Rate limit exceeded (429) - wait before retrying")
            elif status_code >= 500:
                logger.error("Server error (%d) - service temporarily unavailable", status_code)
            else:
                logger.error("HTTP error %d: %s", status_code, e.response.text)
            raise
        except httpx.HTTPError as e:
            logger.error("HTTP error when fetching jobs: %s", str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        reraise=True
    )
    async def fetch_job_by_id(self, job_id: str) -> dict[str, Any]:
        """
        Fetch a specific job by job_id with automatic retry.

        Args:
            job_id: Job identifier

        Returns:
            Job dictionary
        """
        url = f"{self.base_url}/api/v1/jobs"
        params = {"jobId": job_id}

        logger.info("Fetching job with job_id=%s", job_id)

        try:
            response = await self.client.get(url, params=params, headers=self._get_headers())
            response.raise_for_status()
            jobs = response.json()
            # API returns a list, get the first one
            if isinstance(jobs, list) and len(jobs) > 0:
                logger.info("Successfully fetched job %s", job_id)
                return jobs[0]
            elif isinstance(jobs, dict):
                return jobs
            else:
                logger.error("No job found with job_id=%s", job_id)
                raise ValueError(f"Job not found: {job_id}")
        except httpx.TimeoutException:
            logger.error("Request timed out fetching job %s - server may be overloaded", job_id)
            raise
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            if status_code == 401:
                logger.error("Authentication failed (401) - check API_TOKEN")
            elif status_code == 404:
                logger.error("Job not found (404): %s", job_id)
            elif status_code == 429:
                logger.error("Rate limit exceeded (429) - wait before retrying")
            elif status_code >= 500:
                logger.error("Server error (%d) - service unavailable", status_code)
            else:
                logger.error("HTTP error %d: %s", status_code, e.response.text)
            raise
        except httpx.HTTPError as e:
            logger.error("Failed to fetch job %s: %s", job_id, str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        reraise=True
    )
    async def fetch_traces(self, job_id: str) -> list[dict[str, Any]]:
        """
        Fetch traces for a specific job with automatic retry.

        Args:
            job_id: Job identifier

        Returns:
            List of trace dictionaries
        """
        url = f"{self.base_url}/api/v1/traces/all"
        params = {"jobId": job_id}  # API uses camelCase

        logger.info("Fetching traces for job_id=%s", job_id)

        try:
            response = await self.client.get(url, params=params, headers=self._get_headers())
            response.raise_for_status()
            traces = response.json()
            logger.info("Fetched %d traces for job %s", len(traces) if isinstance(traces, list) else 0, job_id)
            return traces if isinstance(traces, list) else []
        except httpx.TimeoutException:
            logger.error("Request timed out fetching traces for job %s", job_id)
            raise
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            if status_code == 401:
                logger.error("Authentication failed (401) - check API_TOKEN")
            elif status_code == 404:
                logger.error("Traces not found (404) for job %s", job_id)
            elif status_code >= 500:
                logger.error("Server error (%d) - service unavailable", status_code)
            else:
                logger.error("HTTP error %d: %s", status_code, e.response.text)
            raise
        except httpx.HTTPError as e:
            logger.error("Failed to fetch traces for job %s: %s", job_id, str(e))
            raise

    async def submit_evaluation(self,
                                job_id: str,
                                trace_id: str,
                                cve: str,
                                component: str,
                                component_version: str,
                                execution_start_timestamp: str,
                                evaluation_results: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Submit evaluation results for a job.

        Args:
            job_id: Job identifier
            trace_id: Trace identifier
            cve: CVE identifier
            component: Component name (e.g., "werkzeug")
            component_version: Component version (e.g., "3.0.5")
            execution_start_timestamp: Execution start timestamp (ISO format)
            evaluation_results: List of evaluation metric dicts with keys:
                - llm_node: e.g., "CHECKLIST_GENERATION", "AGENT_LOOP", "CALCULATE_CVE_SCORE"
                - metric_name: e.g., "CHECKLIST_PROMPT_ALIGNMENT", "AGENT_LOOP_ANSWER_QUALITY"
                - metric_score: float score (converted to string)
                - metric_reasoning: reasoning text
                - model_input: (only for AGENT_LOOP) checklist question
                - model_output: (only for AGENT_LOOP) agent response

        Returns:
            Response from the API
        """
        url = f"{self.base_url}/api/v1/evals"

        # Build payload as list of evaluation records
        payload = []
        for result in evaluation_results:
            record = {
                "job_id": job_id,
                "execution_start_timestamp": execution_start_timestamp,
                "trace_id": trace_id,
                "cve": cve,
                "component": component,
                "component_version": component_version,
                "llm_node": result.get("llm_node", "UNKNOWN"),
                "metric_name": result.get("metric_name", "UNKNOWN"),
                "metric_score": str(result.get("metric_score", 0.0)),
                "metric_reasoning": result.get("metric_reasoning", ""),
                "model_input": result.get("model_input", ""),
                "model_output": result.get("model_output", ""),
            }

            payload.append(record)

        logger.info("Submitting %d evaluation metrics for job_id=%s", len(payload), job_id)

        # async with httpx.AsyncClient(timeout=self.config.timeout, verify=self.config.verify_ssl) as client:
            # try:
            #     response = await client.post(url, json=payload, headers=self._get_headers())
            #     response.raise_for_status()
            #     result = response.json()
            #     logger.info("Successfully submitted evaluation for job %s", job_id)
            #     return result
        try:
            response = await self.client.post(url, json=payload, headers=self._get_headers())
            response.raise_for_status()
            
            # Handle 204 No Content or empty responses
            if response.status_code == 204:
                logger.info("Successfully submitted evaluation for job %s (204 No Content)", job_id)
                return {"status": "success", "message": "Evaluation submitted"}
            
            if not response.content or len(response.content) == 0:
                logger.info("Successfully submitted evaluation for job %s (empty response)", job_id)
                return {"status": "success", "message": "Evaluation submitted"}
            
            # Try to parse JSON
            try:
                result = response.json()
                logger.info("Successfully submitted evaluation for job %s", job_id)
                return result
            except json.JSONDecodeError as json_err:
                logger.warning("API returned non-JSON response for job %s: %s", job_id, str(json_err))
                logger.info("Treating as successful submission (status code %s)", response.status_code)
                return {"status": "success", "message": "Evaluation submitted (non-JSON response)"}
                
        except httpx.TimeoutException:
            logger.error("Request timed out submitting evaluation for job %s - data may be too large", job_id)
            raise
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            response_text = e.response.text if hasattr(e, 'response') else 'N/A'
            
            if status_code == 400:
                logger.error("Bad request (400) - payload format may be incorrect: %s", response_text[:200])
            elif status_code == 401:
                logger.error("Authentication failed (401) - check API_TOKEN")
            elif status_code == 413:
                logger.error("Payload too large (413) - reduce metrics or data size")
            elif status_code == 429:
                logger.error("Rate limit exceeded (429) - wait before retrying")
            elif status_code >= 500:
                logger.error("Server error (%d) - service unavailable: %s", status_code, response_text[:200])
            else:
                logger.error("HTTP error %d: %s", status_code, response_text[:200])
            raise
        except httpx.HTTPError as e:
            logger.error("Failed to submit evaluation for job %s: %s", job_id, str(e))
            raise

    def load_from_local_files(self, jobs_file: str, traces_file: str) -> tuple[list[dict], list[dict]]:
        """
        Load jobs and traces from local JSON files with error handling.

        Args:
            jobs_file: Path to jobs.json
            traces_file: Path to traces.json

        Returns:
            Tuple of (jobs, traces)
            
        Raises:
            FileNotFoundError: If file does not exist
            json.JSONDecodeError: If file contains invalid JSON
            PermissionError: If file cannot be read
        """
        from pathlib import Path

        logger.info("Loading from local files: jobs=%s, traces=%s", jobs_file, traces_file)

        # Load jobs file
        try:
            jobs_path = Path(jobs_file)
            if not jobs_path.exists():
                logger.error("Jobs file not found: %s", jobs_file)
                raise FileNotFoundError(f"Jobs file does not exist: {jobs_file}")
            
            with open(jobs_file, 'r') as f:
                jobs = json.load(f)
            
            if not isinstance(jobs, list):
                jobs = [jobs]
            logger.info("Loaded %d jobs from %s", len(jobs), jobs_file)
                
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in jobs file: %s", jobs_file)
            logger.error("JSON error at line %d column %d: %s", e.lineno, e.colno, e.msg)
            logger.error("Please check the file format")
            raise
        except PermissionError:
            logger.error("Permission denied when reading jobs file: %s", jobs_file)
            raise

        # Load traces file
        try:
            traces_path = Path(traces_file)
            if not traces_path.exists():
                logger.error("Traces file not found: %s", traces_file)
                raise FileNotFoundError(f"Traces file does not exist: {traces_file}")
            
            with open(traces_file, 'r') as f:
                traces = json.load(f)
            
            if not isinstance(traces, list):
                traces = [traces]
            logger.info("Loaded %d traces from %s", len(traces), traces_file)
                
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in traces file: %s", traces_file)
            logger.error("JSON error at line %d column %d: %s", e.lineno, e.colno, e.msg)
            logger.error("Please check the file format")
            raise
        except PermissionError:
            logger.error("Permission denied when reading traces file: %s", traces_file)
            raise

        logger.info("Successfully loaded %d jobs and %d traces", len(jobs), len(traces))
        return jobs, traces
