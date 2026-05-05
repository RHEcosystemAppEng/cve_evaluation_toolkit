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
Extract evaluation data from pipeline outputs.

Supports markdown reports and JSON outputs.
"""

import json
import re
from pathlib import Path
from typing import Any
from typing import Optional

from pydantic import BaseModel
from pydantic import Field

from evaluation.utils.logger import get_logger
logger = get_logger(__name__)

class ChecklistStep(BaseModel):
    """A single checklist step with title and question."""

    step_number: int = Field(description="Step number (1, 2, 3, ...)")
    title: str = Field(description="Step title, e.g., 'Assess Input Data Handling'")
    question: str = Field(description="Full investigation question")
    full_text: str = Field(description="Complete text from the Input field")

    class Config:
        extra = "allow"


class ToolCall(BaseModel):
    """A single tool call within a checklist step investigation."""

    step_id: str = Field(description="Sub-step ID, e.g., '1.1', '2.3'")
    tool_name: str = Field(description="Tool used, e.g., 'Function Locator', 'Code Keyword Search'")
    thought: str = Field(default="", description="Agent's reasoning before tool call")
    action: str = Field(default="", description="Action taken (usually same as tool_name)")
    action_input: str = Field(default="", description="Input to the tool from action log")
    tool_input: str = Field(default="", description="Actual tool input (from Tool Input section)")
    tool_output: str = Field(default="", description="Output from the tool")

    class Config:
        extra = "allow"


class ChecklistStepDetail(BaseModel):
    """Detailed checklist step with tool calls and response."""

    step_number: int = Field(description="Step number (1, 2, 3, ...)")
    title: str = Field(description="Step title/question")
    question: str = Field(description="Full investigation question")
    response: str = Field(default="", description="Agent's final response for this step")
    tool_calls: list[ToolCall] = Field(default_factory=list, description="All tool calls made for this step")
    raw_spans: list[dict] = Field(default_factory=list, description="Raw trace spans for flexible formatting")

    class Config:
        extra = "allow"


class CVEAnalysisResult(BaseModel):
    """
    Structured CVE analysis result for evaluation.

    Follows Pydantic patterns used throughout vuln_analysis.
    """
    cve_id: str = Field(description="CVE identifier")
    job_id: str = Field(default="", description="Job identifier from API")
    trace_id: str = Field(default="", description="Trace identifier for this execution")
    execution_start_timestamp: str = Field(default="", description="Execution start timestamp")
    component: str = Field(default="unknown", description="Component/repository URL or application name")
    component_version: str = Field(default="unknown", description="Component version or git commit hash")
    description: str = Field(default="", description="CVE description text")
    summary: str = Field(default="", description="Analysis summary")
    justification_label: str = Field(default="",
                                     description="Justification label (e.g., 'vulnerable', 'not_vulnerable')")
    justification_reason: str = Field(default="", description="Detailed justification reasoning")
    affected_status: str = Field(default="", description="Affected status from analysis")

    # Checklist data
    checklist_steps: list[ChecklistStep] = Field(default_factory=list,
                                                 description="Structured checklist steps with title and question")
    checklist_items: list[str] = Field(default_factory=list,
                                       description="List of full checklist questions (for backward compatibility)")
    checklist_step_details: list[ChecklistStepDetail] = Field(
        default_factory=list, description="Detailed checklist steps with tool calls and responses")

    action_logs: list[dict[str, Any]] = Field(default_factory=list, description="Agent action logs (ReAct traces)")
    intermediate_steps: list[dict[str, Any]] = Field(default_factory=list, description="Intermediate agent steps")
    intel_score: Optional[int] = Field(default=None, description="Intelligence score if available")

    class Config:
        """Pydantic configuration."""
        extra = "allow"


class MarkdownExtractor:
    """Extract evaluation data from markdown reports."""

    @staticmethod
    def extract_from_file(filepath: str) -> CVEAnalysisResult:
        """
        Extract CVE analysis from a markdown file.

        Args:
            filepath: Path to the markdown file

        Returns:
            CVEAnalysisResult with extracted data
        """
        logger.debug("Extracting from markdown file: %s", filepath)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return MarkdownExtractor.extract_from_content(content)

    @staticmethod
    def extract_from_content(content: str) -> CVEAnalysisResult:
        """
        Extract CVE analysis from markdown content.

        Args:
            content: Markdown content string

        Returns:
            CVEAnalysisResult with extracted data
        """
        result_data: dict[str, Any] = {"cve_id": ""}

        # Extract CVE ID
        cve_match = re.search(r'CVE-\d{4}-\d+', content)
        if cve_match:
            result_data["cve_id"] = cve_match.group(0)

        # =================================================================
        # Extract CVE Description
        # Located between the cve-intro anchor and the first ### section
        # Pattern: after <a name='cve-intro'...> and before ### Severity/Remediation/Related
        # =================================================================
        desc_pattern = r"<a name=['\"]cve-intro['\"].*?>\s*</a>\s*\n.*?\n\n\s*(.+?)(?=\n###)"
        desc_match = re.search(desc_pattern, content, re.DOTALL)
        if desc_match:
            description = desc_match.group(1).strip()
            # Clean up HTML tags and markdown
            description = re.sub(r'<[^>]+>', '', description)
            description = re.sub(r'\s+', ' ', description).strip()
            result_data["description"] = description

        # Extract Summary
        summary_match = re.search(r'### Summary.*?\n(.+?)(?=###|\n---)', content, re.DOTALL)
        if summary_match:
            summary = summary_match.group(1).strip()
            # Clean HTML and markdown
            summary = re.sub(r'<[^>]+>', '', summary)
            summary = re.sub(r'\*\*|\*|`', '', summary)
            result_data["summary"] = summary

        # Extract Justification Label
        label_match = re.search(r'>label:\s*(\w+)', content)
        if label_match:
            result_data["justification_label"] = label_match.group(1)

        # Extract Justification Reason
        reason_match = re.search(r'>label:.*?\n\n(.+?)(?=\n---)', content, re.DOTALL)
        if reason_match:
            result_data["justification_reason"] = reason_match.group(1).strip()

        # Extract Status
        status_match = re.search(r"Status.*?<span[^>]*>([^<]+)</span>", content)
        if status_match:
            result_data["affected_status"] = status_match.group(1).strip()

        # =================================================================
        # Extract Checklist Steps
        # Pattern in MD:
        #   ## Step N ... : {Title}
        #   > **Input**: *{Title}: {Full Question}*
        # =================================================================
        checklist_steps: list[ChecklistStep] = []
        checklist_items: list[str] = []

        # Find all Input fields: > **Input**: *content here*
        input_pattern = r'>\s*\*\*Input\*\*:\s*\*([^*]+)\*'
        input_matches = re.findall(input_pattern, content)

        for i, input_text in enumerate(input_matches, 1):
            input_text = input_text.strip()

            # Split by first colon to separate title and question
            # Format: "Title: Full question here..."
            if ':' in input_text:
                colon_idx = input_text.index(':')
                title = input_text[:colon_idx].strip()
                question = input_text[colon_idx + 1:].strip()
            else:
                title = input_text
                question = ""

            step = ChecklistStep(step_number=i, title=title, question=question, full_text=input_text)
            checklist_steps.append(step)

            # For backward compatibility, store the full text
            checklist_items.append(input_text)

        # Extract Action Logs (ReAct traces) - for backward compatibility
        action_logs: list[dict[str, Any]] = []
        action_log_matches = re.findall(r'#### Action Log\s*\n<pre>(.+?)</pre>', content, re.DOTALL)
        for log in action_log_matches:
            parsed = MarkdownExtractor._parse_action_log(log)
            action_logs.append(parsed)

        # =================================================================
        # Extract Detailed Checklist Steps with Tool Calls
        # =================================================================
        checklist_step_details = MarkdownExtractor._extract_checklist_step_details(content)

        cve_id = result_data.get("cve_id", "")
        logger.debug("Extracted CVE: %s with %d checklist steps, %d detailed steps",
                     cve_id,
                     len(checklist_steps),
                     len(checklist_step_details))

        return CVEAnalysisResult(cve_id=cve_id,
                                 description=result_data.get("description", ""),
                                 summary=result_data.get("summary", ""),
                                 justification_label=result_data.get("justification_label", ""),
                                 justification_reason=result_data.get("justification_reason", ""),
                                 affected_status=result_data.get("affected_status", ""),
                                 checklist_steps=checklist_steps,
                                 checklist_items=checklist_items,
                                 checklist_step_details=checklist_step_details,
                                 action_logs=action_logs)

    @staticmethod
    def _parse_action_log(log: str) -> dict[str, Any]:
        """
        Parse a single action log into structured format.

        Args:
            log: Raw action log string

        Returns:
            Dictionary with parsed thoughts, actions, inputs, and observations
        """
        parsed = {"thoughts": [], "actions": [], "action_inputs": [], "observations": [], "raw": log}

        # Extract Thoughts
        thoughts = re.findall(r'Thought:\s*(.+?)(?=Action:|$)', log, re.DOTALL)
        parsed["thoughts"] = [t.strip() for t in thoughts]

        # Extract Actions
        actions = re.findall(r'Action:\s*(.+?)(?=Action Input:|$)', log, re.DOTALL)
        parsed["actions"] = [a.strip() for a in actions]

        # Extract Action Inputs
        inputs = re.findall(r'Action Input:\s*(.+?)(?=Observation:|Thought:|$)', log, re.DOTALL)
        parsed["action_inputs"] = [i.strip() for i in inputs]

        return parsed

    @staticmethod
    def _extract_checklist_step_details(content: str) -> list[ChecklistStepDetail]:
        """
        Extract detailed checklist steps with tool calls and responses.

        Args:
            content: Markdown content string

        Returns:
            List of ChecklistStepDetail objects with tool calls
        """
        checklist_step_details: list[ChecklistStepDetail] = []

        # Find all main step sections: ## Step N <a name='checklist-step-N'...> : Title
        # Split content by main step headers
        main_step_pattern = r'## Step (\d+)\s*<a name=[\'"]checklist-step-(\d+)[\'"][^>]*>'
        main_step_matches = list(re.finditer(main_step_pattern, content))

        for idx, match in enumerate(main_step_matches):
            step_num = int(match.group(1))

            # Find the end of this step section (next main step or References)
            start_pos = match.start()
            if idx + 1 < len(main_step_matches):
                end_pos = main_step_matches[idx + 1].start()
            else:
                # Find References section or end of content
                ref_match = re.search(r'\n---\n## References', content[start_pos:])
                if ref_match:
                    end_pos = start_pos + ref_match.start()
                else:
                    end_pos = len(content)

            step_section = content[start_pos:end_pos]

            # Extract title from the step header line
            title_match = re.search(r'## Step \d+.*?:\s*(.+?)(?=\n)', step_section)
            title = title_match.group(1).strip() if title_match else f"Step {step_num}"

            # Extract Input (question)
            input_match = re.search(r'>\s*\*\*Input\*\*:\s*\*([^*]+)\*', step_section)
            question = input_match.group(1).strip() if input_match else title

            # Extract Response
            response_match = re.search(r'>\s*\*\*Response\*\*:\s*\*([^*]+)\*', step_section)
            response = response_match.group(1).strip() if response_match else ""

            # Extract tool calls (sub-steps)
            tool_calls = MarkdownExtractor._extract_tool_calls(step_section, step_num)

            checklist_step_details.append(
                ChecklistStepDetail(step_number=step_num,
                                    title=title,
                                    question=question,
                                    response=response,
                                    tool_calls=tool_calls))

        return checklist_step_details

    @staticmethod
    def _extract_tool_calls(step_section: str, step_num: int) -> list[ToolCall]:
        """
        Extract tool calls from a step section.

        Args:
            step_section: Markdown content for a single checklist step
            step_num: The main step number

        Returns:
            List of ToolCall objects
        """
        tool_calls: list[ToolCall] = []

        # Pattern for sub-steps: ### Step N.X : *Tool Name*
        substep_pattern = rf'### Step {step_num}\.(\d+)\s*:\s*\*([^*]+)\*'
        substep_matches = list(re.finditer(substep_pattern, step_section))

        for idx, match in enumerate(substep_matches):
            substep_num = match.group(1)
            tool_name = match.group(2).strip()

            # Find the content for this substep
            start_pos = match.end()
            if idx + 1 < len(substep_matches):
                end_pos = substep_matches[idx + 1].start()
            else:
                end_pos = len(step_section)

            substep_content = step_section[start_pos:end_pos]

            # Extract Action Log
            action_log_match = re.search(r'#### Action Log\s*\n<pre>(.*?)</pre>', substep_content, re.DOTALL)
            action_log = action_log_match.group(1).strip() if action_log_match else ""

            # Parse Thought, Action, Action Input from action log
            thought = ""
            action = ""
            action_input_from_log = ""

            if action_log:
                # Extract Thought (may start with "Observation:" then "Thought:")
                thought_match = re.search(r'(?:^|Observation:.*?)Thought:\s*(.+?)(?=Action:|$)', action_log, re.DOTALL)
                if not thought_match:
                    thought_match = re.search(r'Thought:\s*(.+?)(?=Action:|$)', action_log, re.DOTALL)
                thought = thought_match.group(1).strip() if thought_match else ""

                action_match = re.search(r'Action:\s*(.+?)(?=Action Input:|$)', action_log, re.DOTALL)
                action = action_match.group(1).strip() if action_match else ""

                action_input_match = re.search(r'Action Input:\s*(.+?)(?=Please wait|Observation:|$)',
                                               action_log,
                                               re.DOTALL)
                action_input_from_log = action_input_match.group(1).strip() if action_input_match else ""

            # Extract Tool Input
            tool_input_match = re.search(r'#### Tool Input\s*\n<pre>(.*?)</pre>', substep_content, re.DOTALL)
            tool_input = tool_input_match.group(1).strip() if tool_input_match else ""
            # Clean up the tool input (remove "Please wait..." messages)
            tool_input = re.sub(r'\nPlease wait.*$', '', tool_input, flags=re.DOTALL).strip()

            # Extract Tool Output
            tool_output_match = re.search(r'#### Tool Output\s*\n<pre>(.*?)</pre>', substep_content, re.DOTALL)
            tool_output = tool_output_match.group(1).strip() if tool_output_match else ""

            tool_calls.append(
                ToolCall(step_id=f"{step_num}.{substep_num}",
                         tool_name=tool_name,
                         thought=thought,
                         action=action or tool_name,
                         action_input=action_input_from_log or tool_input,
                         tool_input=tool_input,
                         tool_output=tool_output))

        return tool_calls


class JSONExtractor:
    """Extract evaluation data from JSON outputs."""

    @staticmethod
    def extract_from_file(filepath: str) -> list[CVEAnalysisResult]:
        """
        Extract CVE analyses from JSON output file.

        Args:
            filepath: Path to JSON file (supports JSONL format)

        Returns:
            List of CVEAnalysisResult objects
        """
        logger.debug("Extracting from JSON file: %s", filepath)
        results = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.extend(JSONExtractor._parse_output(data))
                    except json.JSONDecodeError as e:
                        logger.warning("Invalid JSON at line %d: %s", line_num, str(e))
                        logger.debug("Problematic line: %s", line[:100])
                        continue
        logger.debug("Extracted %d CVE results from JSON", len(results))
        return results

    @staticmethod
    def _parse_output(data: dict[str, Any]) -> list[CVEAnalysisResult]:
        """
        Parse a single JSON output entry.

        Args:
            data: Parsed JSON dictionary

        Returns:
            List of CVEAnalysisResult objects
        """
        results = []

        # Navigate to vulnerabilities
        vulns = data.get("results", {}).get("vulnerabilities", [])

        for vuln in vulns:
            result_data = {
                "cve_id": vuln.get("vuln_id", ""),
                "summary": vuln.get("summary", ""),
                "justification_label": vuln.get("justification", {}).get("label", ""),
                "justification_reason": vuln.get("justification", {}).get("reason", ""),
                "affected_status": vuln.get("affected_status", ""),
                "intel_score": vuln.get("intel_score"),
                "checklist_items": [],
                "checklist_steps": [],
                "intermediate_steps": []
            }

            # Extract checklist results with intermediate steps
            checklist_results = vuln.get("checklist_results", [])
            for i, item in enumerate(checklist_results, 1):
                if isinstance(item, dict):
                    input_text = item.get("input", "")
                    if input_text:
                        result_data["checklist_items"].append(input_text)

                        # Parse title and question
                        if ':' in input_text:
                            colon_idx = input_text.index(':')
                            title = input_text[:colon_idx].strip()
                            question = input_text[colon_idx + 1:].strip()
                        else:
                            title = input_text
                            question = ""

                        result_data["checklist_steps"].append(
                            ChecklistStep(step_number=i, title=title, question=question, full_text=input_text))

                    if item.get("intermediate_steps"):
                        result_data["intermediate_steps"].extend(item["intermediate_steps"])

            results.append(CVEAnalysisResult(**result_data))

        return results


class APIExtractor:
    """
    Extract evaluation data from API responses (jobs and traces).

    Data Sources:
    -------------
    1. Job Output (jobOutput.job_output.analysis):
       - checklist: List of checklist items with input/response/intermediate_steps
       - summary: Final summary text
       - justification: Label and reason
       - intel_score: Calculated score

    2. Traces (LLM execution traces):
       - Identified by: nat.span.kind = "LLM" or nat.event_type = "LLM_START"
       - Grouped by: nat.function.name (e.g., cve_checklist, cve_summarize, cve_justify)
       - Contains: input.value (prompt), output.value (completion), token counts

    Extraction Strategy:
    -------------------
    - Primary: Extract from jobOutput (already processed results)
    - Fallback: Extract from LLM traces if jobOutput is missing
    - Enhancement: Use LLM traces for detailed analysis (input/output validation)

    Key LLM Functions to Look For:
    ------------------------------
    - cve_checklist: Generates checklist items
    - cve_agent_executor: Executes agent with tools (Thought/Action/Observation)
    - cve_summarize: Generates final summary
    - cve_justify: Generates justification (label + reason)
    - cve_calculate_intel_score: Calculates intel score with breakdown

    Notes:
    ------
    - Some traces may be missing (e.g., sample data lacks cve_agent_executor traces)
    - In such cases, fall back to jobOutput data
    - Use filter_llm_traces() and group_llm_traces_by_function() to analyze LLM calls
    """

    @staticmethod
    def extract_from_job(job: dict[str, Any], traces: list[dict[str, Any]]) -> Optional[CVEAnalysisResult]:
        """
        Extract CVE analysis data from API job and traces.

        Data sources:
        - Job (jobOutput): Simple fields (summary, justification, checklist questions)
        - Traces: Complex fields (description, intel score details, investigation steps)

        Note: API returns traces for a single execution per job_id, so all traces
        share the same trace_id and execution_start_timestamp.

        Args:
            job: Job dictionary from exploit-iq-client API
            traces: List of trace dictionaries for the job

        Returns:
            CVEAnalysisResult with extracted data, or None if extraction fails
        """
        try:
            job_id = job.get("job_id", "")
            cve_id = job.get("cve", "")
            component = job.get("component", "unknown")
            component_version = job.get("component_version", "unknown")

            logger.info("Extracting from job %s, CVE %s", job_id, cve_id)

            if not traces or len(traces) == 0:
                logger.warning("No traces provided for job %s", job_id)
                return None

            logger.info("Processing %d traces for job %s", len(traces), job_id)

            # Extract trace_id and timestamp from first trace (all traces have same values)
            trace_id = traces[0].get("trace_id", "")
            execution_start_timestamp = traces[0].get("execution_start_timestamp", "")

            logger.info("Trace ID: %s, Timestamp: %s",
                        trace_id[:16] + "..." if trace_id else "N/A",
                        execution_start_timestamp)

            # === 1. Extract simple fields from Job ===
            job_output = job.get("jobOutput", {}).get("job_output", {})
            analysis = job_output.get("analysis", [{}])[0] if job_output.get("analysis") else {}

            summary = analysis.get("summary", "")
            justification = analysis.get("justification", {})
            justification_label = justification.get("label", "")
            justification_reason = justification.get("reason", "")

            # Intel score from job (if available)
            job_intel_score = analysis.get("intel_score")

            # Extract CVE description from VEX data (with fallback to traces)
            description = ""
            vex_data = job_output.get("vex")

            # Check if vex_data is not None before accessing it
            if vex_data is not None:
                vulnerabilities = vex_data.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    if vuln.get("cve") == cve_id:
                        # Find description in notes
                        notes = vuln.get("notes", [])
                        for note in notes:
                            if note.get("category") == "description":
                                description = note.get("text", "")
                                logger.info("Found CVE description in jobOutput VEX data (%d chars)", len(description))
                                break
                        if description:
                            break

            # Fallback: If description not found in VEX (or VEX is None), extract from traces
            if not description:
                logger.warning("CVE description not found in VEX data for %s, trying traces...", cve_id)
                description = APIExtractor._extract_cve_description(cve_id, traces)

                if description:
                    logger.info("Found CVE description from traces (%d chars)", len(description))
                else:
                    logger.warning("WARNING: CVE description not available from VEX or traces for %s", cve_id)

            # Extract checklist questions from job (note: intermediate_steps is usually empty)
            checklist_raw = analysis.get("checklist", [])
            checklist_questions = []
            checklist_steps = []

            for i, item in enumerate(checklist_raw, 1):
                if isinstance(item, dict):
                    question = item.get("input", "")
                    if question:
                        checklist_questions.append(question)

                        # Parse title from question
                        if ':' in question:
                            colon_idx = question.index(':')
                            title = question[:colon_idx].strip()
                        else:
                            title = question[:100] if len(question) > 100 else question

                        checklist_steps.append(
                            ChecklistStep(step_number=i, title=title, question=question, full_text=question))

            logger.info("Extracted from job: %d checklist questions, summary=%d chars, justification=%s",
                        len(checklist_questions),
                        len(summary),
                        justification_label)

            # === 2. Extract complex fields from Traces ===

            # Intel Score (from cve_calculate_intel_score LLM trace)
            trace_intel_score, intel_breakdown, intel_justifications = APIExtractor._extract_intel_score_from_traces(traces)

            # Prefer intel_score from trace (more detailed), fallback to job if not available
            final_intel_score = trace_intel_score if trace_intel_score is not None else job_intel_score

            # Investigation Steps (from LangGraph thought/observation nodes)
            # Extract with raw spans for flexible formatting
            checklist_step_details = APIExtractor._extract_agent_investigation_from_traces(traces, checklist_raw)

            logger.info("Extracted from traces: description=%d chars, intel_score=%s, investigation_steps=%d",
                        len(description),
                        final_intel_score,
                        len(checklist_step_details))

            # === 3. Build result ===
            result = CVEAnalysisResult(cve_id=cve_id,
                                       job_id=job_id,
                                       trace_id=trace_id,
                                       execution_start_timestamp=execution_start_timestamp,
                                       component=component,
                                       component_version=component_version,
                                       description=description,
                                       summary=summary,
                                       justification_label=justification_label,
                                       justification_reason=justification_reason,
                                       checklist_steps=checklist_steps,
                                       checklist_items=checklist_questions,
                                       checklist_step_details=checklist_step_details,
                                       intel_score=final_intel_score)

            # Add extra fields
            if intel_breakdown:
                result.__dict__["intel_score_breakdown"] = intel_breakdown
            if intel_justifications:
                result.__dict__["intel_score_justifications"] = intel_justifications

            logger.info("Successfully extracted CVE %s: %d checklist steps, %d investigation steps",
                        cve_id,
                        len(checklist_steps),
                        len(checklist_step_details))

            return result

        except Exception as e:
            logger.error("Failed to extract from API job %s: %s", job.get("job_id"), e, exc_info=True)
            return None

    @staticmethod
    def _extract_cve_description(cve_id: str, traces: list[dict[str, Any]]) -> str:
        """
        Extract CVE description from cve_fetch_intel FUNCTION trace.

        Data location: nat.event_type = "FUNCTION_START" + nat.function.name = "cve_fetch_intel"
        Field: output.value JSON -> info.intel[].nvd.cve_description
        """
        try:
            for trace in traces:
                try:
                    attrs = trace["spanPayload"]["span_payload"]["attributes"]
                    event_type = attrs.get("nat.event_type", {}).get("stringValue", "")
                    func_name = attrs.get("nat.function.name", {}).get("stringValue", "")

                    if event_type == "FUNCTION_START" and func_name == "cve_fetch_intel":
                        output_val = attrs.get("output.value", {}).get("stringValue", "")

                        if not output_val:
                            continue

                        try:
                            output_json = json.loads(output_val)
                            intel_list = output_json.get("info", {}).get("intel", [])
                        except json.JSONDecodeError as e:
                            logger.warning("Failed to parse CVE output JSON: %s", str(e))
                            continue

                        for intel_item in intel_list:
                            try:
                                if intel_item.get("vuln_id") != cve_id:
                                    continue

                                rhsa_details = intel_item.get("rhsa", {}).get("details")
                                rhsa_desc = rhsa_details[0] if isinstance(rhsa_details, list) and rhsa_details else ""

                                desc = (
                                    intel_item.get("nvd", {}).get("cve_description")
                                    or intel_item.get("ghsa", {}).get("description")
                                    or rhsa_desc
                                )

                                if desc:
                                    logger.info("Found CVE description from cve_fetch_intel trace")
                                    return desc.strip()

                            except (TypeError, AttributeError):
                                continue

                except (KeyError, TypeError):
                    continue

            logger.warning("CVE description not found in traces for %s", cve_id)
            return ""

        except Exception as e:
            logger.error("Error extracting CVE description: %s", e)
            return ""

    @staticmethod
    def _extract_agent_investigation_from_traces(traces: list[dict[str, Any]],
                                                 checklist_items: list[dict]) -> list[ChecklistStepDetail]:
        """
        Extract investigation steps from LangGraph trace format using parent_span_id hierarchy.
        
        Strategy:
        1. Collect checklist_question spans (top-level grouping)
        2. Recursively collect all descendant spans (thought/observation/tool nodes)
        3. Match checklist_question spans to checklist_items by order
        4. Questions come from job data (not from traces)
        
        Args:
            traces: List of trace spans
            checklist_items: List of checklist dict items from job (with 'input' and 'response')
        
        Returns:
            List of ChecklistStepDetail objects with investigation details and raw spans
        """
        NODE_FUNCTION_NAMES = {"thought node", "observation node", "pre_process node"}
        
        # Helper: Get string attribute value
        def get_attr_str(attrs: dict, key: str) -> str:
            return attrs.get(key, {}).get("stringValue", "")
        
        # Helper: Safe float conversion
        def safe_float(value, default=float('inf')):
            """Convert to float, returning default for None/empty/invalid values."""
            if value is None or value == "":
                return default
            try:
                return float(value)
            except (ValueError, TypeError):
                return default
        
        def safe_timestamp(value, default=None):
            """Convert to float timestamp, None if invalid."""
            if not value:
                return default
            try:
                return float(value)
            except (ValueError, TypeError):
                return default
        
        # Helper: Recursively collect all descendant spans
        def collect_descendants(parent_id: str, parent_map: dict, depth: int = 0, max_depth: int = 5) -> list[dict]:
            """Recursively collect all child and grandchild spans"""
            if depth > max_depth:
                return []
            
            descendants = []
            direct_children = parent_map.get(parent_id, [])
            
            for child in direct_children:
                descendants.append(child)
                # Recursively collect grandchildren
                grandchildren = collect_descendants(child['span_id'], parent_map, depth + 1, max_depth)
                descendants.extend(grandchildren)
            
            return descendants
        
        # Step 1: Collect checklist_question spans
        checklist_spans = []
        for trace in traces:
            attrs = trace.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
            metadata = trace.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
            
            func_name = get_attr_str(attrs, "nat.function.name")
            event_type = get_attr_str(attrs, "nat.event_type")
            
            if func_name == "checklist_question" and event_type == "FUNCTION_START":
                checklist_spans.append({
                    "span_id": (metadata.get("span_id") or "")[:16],
                    "start_time": get_attr_str(attrs, "nat.event_timestamp"),
                })
        
        # Sort by time to ensure order
        checklist_spans = [s for s in checklist_spans if safe_timestamp(s.get("start_time")) is not None]
        checklist_spans.sort(key=lambda s: safe_timestamp(s.get("start_time"), 0.0))
        
        logger.info("Collected %d checklist_question spans", len(checklist_spans))
        
        # Step 2: Collect all agent spans and build parent index
        parent_to_children = {}
        
        for trace in traces:
            attrs = trace.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
            metadata = trace.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
            
            func_name = get_attr_str(attrs, "nat.function.name")
            subspan_name = get_attr_str(attrs, "nat.subspan.name")
            event_type = get_attr_str(attrs, "nat.event_type")
            
            span_id = (metadata.get("span_id") or "")[:16]
            parent_span_id = (metadata.get("parent_span_id") or "")[:16]
            
            # Collect agent spans (thought/observation/tool)
            if func_name in NODE_FUNCTION_NAMES:
                span_data = {
                    "span_id": span_id,
                    "parent_span_id": parent_span_id,
                    "function_name": func_name,
                    "subspan_name": subspan_name,
                    "span_kind": "FUNCTION",
                    "event_type": event_type,
                    "input_value": get_attr_str(attrs, "input.value"),
                    "output_value": get_attr_str(attrs, "output.value"),
                    "start_time": get_attr_str(attrs, "nat.event_timestamp"),
                    "token_prompt": attrs.get("llm.token_count.prompt", {}).get("intValue", 0),
                    "token_completion": attrs.get("llm.token_count.completion", {}).get("intValue", 0),
                }
                parent_to_children.setdefault(parent_span_id, []).append(span_data)
            
            elif event_type == "TOOL_START":
                span_data = {
                    "span_id": span_id,
                    "parent_span_id": parent_span_id,
                    "function_name": subspan_name or func_name,
                    "subspan_name": subspan_name,
                    "span_kind": "TOOL",
                    "event_type": event_type,
                    "input_value": get_attr_str(attrs, "input.value"),
                    "output_value": get_attr_str(attrs, "output.value"),
                    "start_time": get_attr_str(attrs, "nat.event_timestamp"),
                    "token_prompt": attrs.get("llm.token_count.prompt", {}).get("intValue", 0),
                    "token_completion": attrs.get("llm.token_count.completion", {}).get("intValue", 0),
                }
                parent_to_children.setdefault(parent_span_id, []).append(span_data)
        
        logger.info("Built parent index with %d unique parents", len(parent_to_children))
        
        # Step 3: Match checklist_items to checklist_question spans by order
        investigation_steps = []
        
        for i, checklist_item in enumerate(checklist_items, 1):
            question = checklist_item.get("input", "")
            response = checklist_item.get("response", "")
            
            if not question:
                continue
            
            # Match by order (i-1 because enumerate starts at 1)
            if i - 1 < len(checklist_spans):
                cq_span_id = checklist_spans[i - 1]["span_id"]
                
                # Recursively collect all descendant spans
                all_descendants = collect_descendants(cq_span_id, parent_to_children)
                
                # Sort by time
                all_descendants.sort(key=lambda s: safe_float(s.get("start_time")))                
                logger.debug("Question %d: Collected %d descendant spans", i, len(all_descendants))
                
                # Build tool_calls for backward compatibility
                tool_calls = APIExtractor._build_tool_calls_from_spans(all_descendants)
                
                # Save ChecklistStepDetail with raw_spans
                investigation_steps.append(
                    ChecklistStepDetail(
                        step_number=i,
                        title=question[:100] if len(question) > 100 else question,
                        question=question,
                        response=response,
                        tool_calls=tool_calls,
                        raw_spans=all_descendants
                    )
                )
                
                logger.debug("Extracted investigation step %d: %s (%d spans, %d tool calls)",
                            i,
                            question[:50],
                            len(all_descendants),
                            len(tool_calls))
            else:
                # No matching checklist_question span
                logger.warning("No matching checklist_question span for question %d: %s", i, question[:50])
                investigation_steps.append(
                    ChecklistStepDetail(
                        step_number=i,
                        title=question[:100] if len(question) > 100 else question,
                        question=question,
                        response=response,
                        tool_calls=[],
                        raw_spans=[]
                    )
                )
        
        logger.info("Extracted %d investigation steps from %d checklist items",
                    len(investigation_steps),
                    len(checklist_items))
        return investigation_steps

    @staticmethod
    def _build_tool_calls_from_spans(spans: list[dict]) -> list[ToolCall]:
        """
        Build ToolCall objects from raw spans (thought/observation/tool nodes).
        
        Extracts complete information including thought, reason, tool, and observation.
        
        Args:
            spans: List of raw span dictionaries
        
        Returns:
            List of ToolCall objects
        """
        tool_calls = []
        current_thought = ""
        current_reason = ""
        step_id = 1
        obs_index = APIExtractor._build_observation_index(spans)
        for idx, span in enumerate(spans):
            func_name = span["function_name"]
            span_kind = span.get("span_kind", "FUNCTION")
            
            if func_name == "thought node":
                # Extract thought and actions (including reason)
                # Only process "full" thought nodes that have actual thought content
                # Skip "simple" thought nodes that only have mode/step (length < 50)
                output_value = span.get("output_value", "{}")
                
                if len(output_value) < 50:
                    # Skip simple thought nodes like {"mode": "act", "step": 1}
                    continue
                
                try:
                    thought_json = json.loads(output_value)
                    current_thought = thought_json.get("thought", "")
                    # Extract actions (tool, reason, etc.)
                    actions = thought_json.get("actions") or {}
                    current_reason = actions.get("reason", "")
                except json.JSONDecodeError:
                    # If JSON parse fails, try to extract from string representation
                    current_thought = output_value
                    current_reason = ""
                    
                    # Try to extract thought and reason from malformed JSON string
                    if "thought" in output_value and "reason" in output_value:
                        try:
                            # Attempt to fix common JSON issues
                            import ast
                            parsed = ast.literal_eval(output_value)
                            if isinstance(parsed, dict):
                                current_thought = parsed.get("thought", output_value)
                                current_reason = parsed.get("actions") or {}.get("reason", "")
                        except (ValueError, SyntaxError) as e:
                            logger.debug("Failed to parse thought node with ast.literal_eval: %s", e)
            
            elif span_kind == "TOOL":
                # Tool call span
                tool_name = span.get("subspan_name") or span.get("function_name")
                tool_input = span.get("input_value", "")
                
                # Find next observation node for output
                tool_output = ""
                for j in range(idx + 1, min(idx + 5, len(spans))):  # Check next 4 spans
                    if spans[j]["function_name"] == "observation node":
                        obs_span = spans[j]
                        output_value = obs_span.get("output_value", "")
                        
                        # Skip if output_value is empty or too short (likely metadata only)
                        if not output_value or len(output_value) < 50:
                            continue
                        
                        try:
                            obs_json = json.loads(output_value)
                            
                            # Check if it has results (the actual tool output)
                            if "results" in obs_json:
                                results = obs_json.get("results", [])
                                if isinstance(results, list) and len(results) > 0:
                                    tool_output = "\n".join(str(r)[:2000] for r in results[:5])
                                    break  # Found the real output
                                elif results:  # Non-empty results (not a list)
                                    tool_output = str(results)[:2000]
                                    break
                            
                            # If no results but has content field or other meaningful data
                            elif len(output_value) > 100:  # Substantial content
                                # This might be the actual output in a different format
                                tool_output = output_value[:2000]
                                break
                                
                        except json.JSONDecodeError:
                            # If can't parse as JSON but has substantial content
                            if len(output_value) > 100:
                                tool_output = output_value[:2000]
                                break
                
                # If still no output found, mark as empty
                if not tool_output:
                    tool_output = "[No output captured]"
                
                # Combine thought and reason
                full_thought = current_thought
                if current_reason:
                    full_thought = f"{current_thought}\nReason: {current_reason}"
                
                tool_calls.append(
                    ToolCall(
                        step_id=str(step_id),
                        tool_name=tool_name,
                        thought=full_thought,
                        action=tool_name,
                        action_input=tool_input,
                        tool_input=tool_input,
                        tool_output=tool_output
                    )
                )
                step_id += 1
                current_thought = ""
                current_reason = ""
        
        return tool_calls

    @staticmethod
    def _parse_tool_calls_from_action_log(action_log: str) -> list[ToolCall]:
        """Parse Thought/Action/Action Input/Observation pattern from action log"""

        tool_calls = []

        # Use simple segmentation for parsing (may need adjustment based on actual format)
        # Look for Thought/Action/Action Input/Observation pattern

        # Split by "Thought:", each section represents a thought-action cycle
        sections = re.split(r'\n(?=Thought:)', action_log)

        step_id = 1
        for section in sections:
            if not section.strip():
                continue

            # Extract each part
            thought_match = re.search(r'Thought:\s*(.*?)(?=\nAction:|$)', section, re.DOTALL)
            action_match = re.search(r'Action:\s*(.*?)(?=\nAction Input:|$)', section, re.DOTALL)
            action_input_match = re.search(r'Action Input:\s*(.*?)(?=\nObservation:|$)', section, re.DOTALL)
            observation_match = re.search(r'Observation:\s*(.*?)(?=\nThought:|$)', section, re.DOTALL)

            thought = thought_match.group(1).strip() if thought_match else ""
            action = action_match.group(1).strip() if action_match else ""
            action_input = action_input_match.group(1).strip() if action_input_match else ""
            observation = observation_match.group(1).strip() if observation_match else ""

            # Only add when at least thought or action is present
            if thought or action:
                tool_calls.append(
                    ToolCall(step_id=str(step_id),
                             tool_name=action,
                             thought=thought,
                             action=action,
                             action_input=action_input,
                             tool_input=action_input,
                             tool_output=observation))
                step_id += 1

        return tool_calls

    @staticmethod
    def _extract_intel_score_from_traces(
            traces: list[dict[str, Any]]) -> tuple[Optional[int], Optional[dict], Optional[dict]]:
        """
        Extract intel score and breakdown from cve_calculate_intel_score LLM trace.

        Data location: nat.event_type = "LLM_START" + nat.function.name = "cve_calculate_intel_score"
        Field: output.value JSON -> {"scores": {...}, "justifications": {...}}

        Returns:
            (total_score, scores_breakdown, justifications)
        """
        try:
            for trace in traces:
                try:
                    attrs = trace["spanPayload"]["span_payload"]["attributes"]
                    event_type = attrs.get("nat.event_type", {}).get("stringValue", "")
                    func_name = attrs.get("nat.function.name", {}).get("stringValue", "")

                    # Find LLM_START + cve_calculate_intel_score
                    if event_type == "LLM_START" and func_name == "cve_calculate_intel_score":
                        output_val = attrs.get("output.value", {}).get("stringValue", "")

                        if output_val:
                            try:
                                # output is JSON string
                                output_json = json.loads(output_val)

                                scores = output_json.get("scores", {})
                                justifications = output_json.get("justifications", {})
                            except json.JSONDecodeError as e:
                                logger.warning("Failed to parse intel score JSON: %s", str(e))
                                continue
                            
                            try:

                                if scores:
                                    # Calculate total score
                                    total = sum(scores.values())
                                    logger.info("Extracted intel score %d from traces (breakdown: %d fields)",
                                                total,
                                                len(scores))
                                    return total, scores, justifications

                            except json.JSONDecodeError as e:
                                logger.debug("Failed to parse intel score output JSON: %s", e)
                                pass

                except (KeyError, TypeError):
                    continue

            logger.warning("Intel score not found in traces")
            return None, None, None

        except Exception as e:
            logger.error("Error extracting intel score: %s", e)
            return None, None, None

    @staticmethod
    def filter_traces_by_function(traces: list[dict[str, Any]], function_name: str) -> list[dict[str, Any]]:
        """
        Filter traces by nat.function.name.

        Args:
            traces: List of trace dictionaries
            function_name: Function name to filter by (e.g., 'cve_agent_executor')

        Returns:
            Filtered list of traces
        """
        filtered = []
        for trace in traces:
            try:
                func_name = trace["spanPayload"]["span_payload"]["attributes"]["nat.function.name"]["stringValue"]
                if func_name == function_name:
                    filtered.append(trace)
            except (KeyError, TypeError):
                continue
        return filtered

    @staticmethod
    def filter_llm_traces(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Filter traces to find all LLM-related traces.

        LLM traces have nat.span.kind = "LLM" and nat.event_type = "LLM_START".

        Args:
            traces: List of trace dictionaries

        Returns:
            List of LLM traces
        """
        llm_traces = []
        for trace in traces:
            try:
                span_kind = trace["spanPayload"]["span_payload"]["attributes"].get("nat.span.kind",
                                                                                   {}).get("stringValue", "")
                event_type = trace["spanPayload"]["span_payload"]["attributes"].get("nat.event_type",
                                                                                    {}).get("stringValue", "")

                if span_kind == "LLM" or event_type == "LLM_START":
                    llm_traces.append(trace)
            except (KeyError, TypeError):
                continue

        return llm_traces

    @staticmethod
    def group_llm_traces_by_function(traces: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """
        Group LLM traces by their nat.function.name.

        This helps organize LLM calls by the stage they belong to (e.g., cve_checklist, cve_summarize).

        Args:
            traces: List of trace dictionaries

        Returns:
            Dictionary mapping function names to lists of LLM traces
        """
        llm_traces = APIExtractor.filter_llm_traces(traces)
        grouped = {}

        for trace in llm_traces:
            try:
                func_name = trace["spanPayload"]["span_payload"]["attributes"]["nat.function.name"]["stringValue"]
                if func_name not in grouped:
                    grouped[func_name] = []
                grouped[func_name].append(trace)
            except (KeyError, TypeError):
                continue

        return grouped


def extract_results(source: str) -> list[CVEAnalysisResult]:
    """
    Auto-detect source type and extract results.

    Args:
        source: Path to markdown file, JSON file, or directory

    Returns:
        List of CVEAnalysisResult objects

    Raises:
        ValueError: If source type cannot be determined
    """
    path = Path(source)
    logger.info("Extracting results from: %s", source)

    if path.is_file():
        if path.suffix == '.md':
            return [MarkdownExtractor.extract_from_file(str(path))]
        elif path.suffix == '.json':
            return JSONExtractor.extract_from_file(str(path))
    elif path.is_dir():
        results = []
        md_files = list(path.glob("**/*.md"))
        logger.info("Found %d markdown files in directory", len(md_files))
        for md_file in md_files:
            try:
                results.append(MarkdownExtractor.extract_from_file(str(md_file)))
            except Exception as e:
                logger.warning("Failed to extract from %s: %s", md_file, e)
        return results

    raise ValueError(f"Unknown source type: {source}")
