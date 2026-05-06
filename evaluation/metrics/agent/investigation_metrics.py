# SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
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
Agent Investigation Evaluation Metrics.

4 GEval metrics for evaluating ReAct agent CVE investigation:
1. Answer Quality - Relevancy + Evidence support
2. Reasoning Quality - Logic coherence + Goal focus
3. Tool Selection Quality - Semantic appropriateness (no syntax)
4. Tool Call Integrity - Syntax and schema validation
"""

import json
import os
from typing import Any

from deepeval.metrics import GEval
from deepeval.models.base_model import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase
from deepeval.test_case import LLMTestCaseParams
from pydantic import BaseModel
from pydantic import Field

from evaluation.extractors.data_extractor import ToolCall

# Add logger
try:
    from evaluation.utils.logger import get_logger
    logger = get_logger(__name__, level=os.getenv('LOG_LEVEL', 'INFO'))
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

# ============================================================================
# Tool Definitions (for eval rubrics)
# ============================================================================

TOOL_DESCRIPTIONS = """
AVAILABLE TOOLS AND THEIR PURPOSES:

1. Code Semantic Search
   - Purpose: Search container source code using semantic vector embeddings
   - Use when: Understanding how code works, finding related functionality
   - Input: Natural language query about code behavior

2. Docs Semantic Search
   - Purpose: Search container documentation using semantic vector embeddings
   - Use when: Understanding architecture, design decisions, configuration
   - Input: Natural language query about documentation

3. Code Keyword Search
   - Purpose: Search container source code for exact keyword matches
   - Use when: Looking for specific function names, variable names, imports
   - Input: Exact keywords or patterns to match

4. Function Locator
   - Purpose: Validate package names, locate functions using fuzzy matching
   - Use when: Need to find exact function location before analyzing call chains
   - IMPORTANT: Must be called BEFORE Call Chain Analyzer
   - Input: Package name and function name (format: package,function)

5. Call Chain Analyzer
   - Purpose: Check if a function is reachable from application code
   - Use when: Determining if vulnerable function can be reached/exploited
   - PREREQUISITE: Must call Function Locator first
   - Input: Function identifier from Function Locator

6. Function Caller Finder
   - Purpose: Find functions calling specific standard library methods
   - Use when: Tracing usage of stdlib functions (GOLANG ONLY)
   - Input: Standard library method name

7. CVE Web Search
   - Purpose: Search the web for CVE and vulnerability information
   - Use when: Need external context about exploits, patches, severity
   - Input: CVE ID or vulnerability-related query

8. Container Analysis Data
   - Purpose: Retrieve pre-analyzed data from earlier container scan steps
   - Use when: Need summary of previous analysis findings
   - Input: None (retrieves cached data)
"""

# ============================================================================
# Data Models
# ============================================================================


class InvestigationEvalInput(BaseModel):
    """Input data for investigation evaluation.

    Designed to work with ChecklistStepDetail from the extractor:
    - checklist_question: from ChecklistStepDetail.question
    - final_response: from ChecklistStepDetail.response
    - tool_calls: from ChecklistStepDetail.tool_calls (list of ToolCall)
    - raw_spans: from ChecklistStepDetail.raw_spans (for flexible formatting)
    """

    cve_id: str = Field(description="CVE identifier")
    checklist_question: str = Field(description="The checklist question being investigated")
    final_response: str = Field(default="", description="Agent's final response for this question")
    tool_calls: list[ToolCall] = Field(default_factory=list, description="All tool calls made for this step")
    raw_spans: list[dict] = Field(default_factory=list, description="Raw trace spans for flexible formatting")

    @property
    def has_tool_calls(self) -> bool:
        """Check if this investigation has tool calls."""
        return len(self.tool_calls) > 0
    
    @property
    def has_raw_spans(self) -> bool:
        """Check if this investigation has raw spans."""
        return len(self.raw_spans) > 0

    @classmethod
    def from_step_detail(cls, cve_id: str, step_detail: Any) -> "InvestigationEvalInput":
        """Create from a ChecklistStepDetail object.

        Args:
            cve_id: The CVE identifier
            step_detail: ChecklistStepDetail from the extractor (evaluation.extractors.data_extractor.ChecklistStepDetail)

        Returns:
            InvestigationEvalInput ready for evaluation
        """
        return cls(cve_id=cve_id,
                   checklist_question=step_detail.question,
                   final_response=step_detail.response,
                   tool_calls=step_detail.tool_calls,
                   raw_spans=getattr(step_detail, 'raw_spans', []))


# ============================================================================
# GEval Metrics (4 metrics)
# ============================================================================


def create_answer_quality_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Combined metric: Answer Relevancy + Evidence Quality

    Evaluates BOTH:
    - Does the answer address the question? (relevancy)
    - Is the answer supported by sufficient evidence? (evidence quality)
    """
    return GEval(name="Answer Quality",
                 criteria="""
        Evaluate the quality of the agent's answer in terms of both RELEVANCY
        (does it address the question?) and EVIDENCE SUPPORT (is it backed by findings?).

        INPUT: A CVE investigation checklist question
        ACTUAL OUTPUT: The agent's investigation trace and final answer

        In your reasoning, explicitly reference the specific requirements of this criteria. Use the format: 'The response [meets/fails] the [Specific Criteria Name] because [Evidence from Output], which directly relates to the requirement of [Specific Clause from Criteria].

        EVALUATION DIMENSIONS:

        A. RELEVANCY (50% weight):
        - Does the answer directly address what was asked?
        - Is the answer specific to the question, not generic?
        - Does the conclusion follow from the investigation?
        - **Semantic Equality**: In the context of CVE scanning, the response "I do not have a definitive answer" is SEMANTICALLY EQUIVALENT to "I found no evidence in the current scope." 
        - Do NOT penalize the agent for using a generic refusal if the investigation trace shows that the search results were actually empty/failed. This is an honest, low-risk answer.
        Note: If the investigation trace shows exhaustive searching but no evidence is found, a conclusion stating the inability to confirm (with reasons) is considered RELEVANT and logically sound.

        B. EVIDENCE SUPPORT (50% weight):
        - Is the answer backed by evidence from tool outputs?
        - Are specific citations provided (files, functions, line numbers)?
        - Were multiple sources consulted to verify findings?
        - Did the agent try alternative queries when searches failed?
        - Are limitations/uncertainties acknowledged?

        SCORING RUBRIC:

        Score 0.0-0.2 (CRITICAL FAIL):
        - Answer is completely unrelated to the topic.
        - Agent claims a vulnerability exists when tools say it doesn't.
        - **Note: A "no definitive answer" response is NOT a 0-score if the trace shows relevant tool calls. This is a "Negative Conclusion", not a "No Answer".**
        - **Note: Do NOT use this score just because the response is generic, as long as tool calls were made.**

        Score 0.3-0.5 (ADEQUATE / CONSERVATIVE):
        - **[Target Zone]**: The agent investigated (2+ tool calls) but found no evidence.
        - The agent chooses a conservative "no definitive answer" instead of a summary. 
        - While suboptimal, this shows the agent correctly avoided making up facts. 
        - **This must score at least 0.4 if the investigation steps were relevant to the package or function name.**

        Score 0.6-0.8 (GOOD):
        - Answer clearly addresses the question based on findings.
        - **If the answer is "No" or "Uncertain", the agent must have tried at least 2-3 different logical queries (e.g., package name, then specific function keyword).**
        - Evidence (even if it's "no results found") supports the final conclusion.

        Score 0.9-1.0 (EXCELLENT):
        - Answer thoroughly addresses the question.
        - **For negative findings:** Agent provides a "reasoned denial" (e.g., "I searched for the package X and the specific function Y across the codebase with no results, therefore it is likely not present").
        - **For positive findings:** Comprehensive evidence with specific citations (files, functions).
        - Acknowledges limitations (e.g., "Keyword search returned nothing, but semantic search for the protocol logic also showed no relevant implementation").
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold,
                 verbose_mode=False)


def create_reasoning_quality_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Evaluate logical coherence and goal focus of agent's reasoning.

    Assesses whether the agent's thought process is coherent and stays focused on the investigation goal.
    """
    return GEval(name="Reasoning Quality",
                 criteria="""
        Evaluate the quality of the agent's reasoning process in terms of both
        LOGICAL COHERENCE (is the reasoning sound?) and GOAL FOCUS (does it stay on track?).

        INPUT: A CVE investigation checklist question
        ACTUAL OUTPUT: The agent's structured investigation trace with:
          - Step X - Thought: What the agent plans to investigate
          - Reason: Why this investigation step is needed
          - Planned Tool: The tool the agent will use
          - Observation: Results from the tool execution
          - Final Response: Agent's concluding answer

        The trace shows a sequence of reasoning steps. Each step shows what the agent
        thought, why it chose that approach, and what it discovered.

        In your reasoning, explicitly reference the specific requirements of this criteria. Use the format: 'The response [meets/fails] the [Specific Criteria Name] because [Evidence from Output], which directly relates to the requirement of [Specific Clause from Criteria].

        IMPORTANT: Investigating prerequisite conditions (e.g., "Is function X reachable?")
        is NOT a tangent if it determines whether downstream concerns (e.g., "validation",
        "configurations") are relevant. Such investigation paths should score highly if
        logical and well-justified.

        EVALUATION DIMENSIONS:

        A. LOGICAL COHERENCE (50% weight):
        - **Prerequisite Logic**: If the agent fails to find the package (e.g., 'go-git' returns no results), it is LOGICALLY CORRECT to stop searching for version details or reachability. You cannot analyze a package that doesn't exist.
        - **Refinement Strategy**: If an agent fails a search and retries with a more specific keyword (e.g., adding a module path), this is LOGICAL PROGRESS, even if the 'Thought' or 'Reason' text remains similar to maintain the original goal.
        - **Value of Negative Findings**: Acknowledging that no evidence was found after multiple attempts is a sound logical conclusion.
        - **Defensive conclusion**: "I do not have a definitive answer" is a safe and logical conclusion when tools yield zero hits.
        - **Consistency**: Do NOT penalize the agent for saying "no evidence found" in the trace and "no definitive answer" in the final response; these are logically compatible.

        B. GOAL FOCUS (50% weight):
        - Did the agent stay on the topic of the specific package and vulnerability?
        - Did it attempt at least two different search strategies (e.g., short name vs full path)?

        SCORING RUBRIC:

        Score 0.0-0.2 (CRITICAL FAILURE):
        - Agent made NO tool calls or calls completely unrelated tools.
        - Agent claims a package is present/vulnerable when the tool output explicitly says "no results".
        - **Note: Do NOT use this score if the agent tried different search terms, even if the 'Thought' text is repetitive.**

        Score 0.3-0.5 (MARGINAL / HONEST ATTEMPT):
        - **[MANDATORY SCORE FOR THIS CASE]**: Agent attempts to find the answer using 2+ relevant tool calls.
        - Even if the agent repeats the same 'Thought' or 'Reason' text, as long as the **Tool Query/Input changes** (e.g., refining the package name), it shows a valid investigation attempt.
        - The agent correctly identifies that no evidence was found and provides a cautious final response.
        - *Penalty*: If the agent missed a secondary part of the question (like the version), score it in this 0.4-0.5 range, but NOT lower.

        Score 0.6-0.8 (GOOD):
        - Agent explicitly describes why the previous search failed in the next 'Thought'.
        - Shows a clear progression from broad to specific queries.

        Score 0.9-1.0 (EXCELLENT):
        - Perfect synthesis of all search results.
        - Explains exactly what was tried and why the final conclusion (even if negative) is justified.
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold,
                 verbose_mode=False)


def create_tool_selection_quality_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Evaluate semantic appropriateness of tool selections.

    Focuses on whether the right tools were chosen and used in the correct sequence.
    Does NOT evaluate syntax or schema correctness (see Tool Call Integrity).
    """
    return GEval(name="Tool Selection Quality",
                 criteria=f"""
        Evaluate if the agent selected appropriate tools for investigating the question.

        INPUT: A CVE investigation checklist question
        ACTUAL OUTPUT: The agent's COMPLETE trace with tool sequence

        {TOOL_DESCRIPTIONS}

        In your reasoning, explicitly reference the specific requirements of this criteria. Use the format: 'The response [meets/fails] the [Specific Criteria Name] because [Evidence from Output], which directly relates to the requirement of [Specific Clause from Criteria].

        EVALUATION CRITERIA (SEMANTIC ONLY - syntax is evaluated separately):

        1. TOOL APPROPRIATENESS (40% weight):
        - Is the tool choice semantically relevant? 
        - NOTE: Searching for the package name (e.g., "go-git") via Keyword Search IS a valid first step to confirm the package exists in the codebase, even before locating specific functions.

        2. TOOL SEQUENCE AND DEPENDENCIES (40% weight):
        - Function Locator MUST precede Call Chain Analyzer (dependency!)
        - Function Locator MUST precede Function Caller Finder (dependency!)
        - Does the sequence follow a logical flow: Find Package/Info -> Locate Function -> Analyze Reachability.
        - Do not strictly penalize for skipping "CVE Web Search" if the agent is trying to verify package existence directly in the code.
        - However, repeating the same tool with nearly identical queries after a failure is considered "low efficiency."

        GOOD sequence example:
          Step 1: Function Locator (find the function)
          Step 2: Call Chain Analyzer (trace how it's called)
          Step 3: Code Keyword Search (verify usage context)

        BAD sequence example:
          Step 1: Call Chain Analyzer (ERROR: no function located yet!)
          Step 2: Function Locator (should have been first)

        3. INPUT SEMANTICS (20% weight):
        - Is the search term relevant? (e.g., searching for the package mentioned in the question).
        - Example BAD: Question asks about "werkzeug", but searches for "flask"

        IMPORTANT: Do NOT penalize for syntax errors (wrong format, missing fields).
        That is evaluated separately by Tool Call Integrity metric.

        SCORING RUBRIC:

        Score 0.0-0.2 (CRITICAL FAILURE):
        - Tools used are completely unrelated to the question (e.g., using Docs search for a code reachability question).
        - Direct violation of HARD dependencies (e.g., Call Chain Analyzer used without any prior Function Locator/Search).

        Score 0.3-0.5 (SUBOPTIMAL / INCOMPLETE):
        - The agent made a relevant attempt (e.g., searched for the correct package name) but gave up too early.
        - The sequence is slightly illogical (e.g., should have used Semantic Search to find the 'function related to file transport' instead of just guessing keywords).
        - **This is the appropriate score for agents that try 1-2 relevant searches but fail to find the answer.**

        Score 0.6-0.8 (GOOD):
        - Correct tool choices that align with the investigation goal.
        - Logical progression (e.g., search package -> try to find specific function).
        - Semantic queries are well-targeted.

        Score 0.9-1.0 (EXCELLENT):
        - Optimal path: Used Web/Semantic search to identify the vulnerable function name, then used Locator, then analyzed the chain.
        - Highly efficient; no redundant steps.
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold,
                 verbose_mode=False)


def create_tool_call_integrity_metric(judge_model: DeepEvalBaseLLM, threshold: float = 0.7) -> GEval:
    """
    Evaluate syntax and schema correctness of tool calls.

    Focuses on formatting, required fields, and type correctness.
    Does NOT evaluate semantic appropriateness (see Tool Selection Quality).
    """
    return GEval(
        name="Tool Call Integrity",
        criteria=f"""
        Evaluate if the agent's tool calls follow correct syntax and schema requirements.

        INPUT: A CVE investigation checklist question
        ACTUAL OUTPUT: The agent's trace showing tool calls

        {TOOL_DESCRIPTIONS}

        In your reasoning, explicitly reference the specific requirements of this criteria. Use the format: 'The response [meets/fails] the [Specific Criteria Name] because [Evidence from Output], which directly relates to the requirement of [Specific Clause from Criteria].

        EVALUATION CRITERIA (SYNTAX ONLY, NOT SEMANTIC):

        1. SCHEMA ADHERENCE (30%):
        - Are all required fields present for each tool?
        - Function Locator MUST have format: "package,function" (comma-separated, both parts required)
        - Call Chain Analyzer MUST reference an existing function
        - Are field types correct (string vs object)?

        2. FORMAT CORRECTNESS (30%):
        - Is JSON properly formatted (no malformed brackets, quotes)?
        - Are special characters properly escaped?
        - No syntax errors that would prevent tool execution?
        - Proper string formatting without embedded control characters?

        3. REQUIRED FIELD VALIDATION (40%):
        - Function Locator: Has BOTH package AND function (not just one)?
          CORRECT: "package,function"
          INCORRECT: "function" (missing package)
          INCORRECT: "package," (missing function)
        - Keyword Search: Has non-empty search term?
        - Call Chain Analyzer: Has valid function reference?
        - Each tool has proper "Action Input" format?

        IMPORTANT: This metric checks SYNTAX only, not whether the input makes semantic sense.
        Do NOT penalize if the package name is wrong but formatted correctly.

        SCORING RUBRIC:

        Score 0.0-0.3 (FAIL):
        - Malformed JSON that breaks tool execution
        - Missing required fields (e.g., only "function" without "package")
        - Type errors (e.g., passing array instead of string)
        - Multiple syntax violations

        Score 0.4-0.6 (POOR):
        - Some format errors but tools might still run
        - Inconsistent formatting across tool calls
        - Minor schema violations that could cause issues

        Score 0.7-0.8 (GOOD):
        - All required fields present with correct types
        - Proper JSON formatting
        - Schema requirements met
        - Minor formatting inconsistencies only

        Score 0.9-1.0 (EXCELLENT):
        - Perfect schema adherence throughout
        - Clean, properly formatted inputs
        - All type requirements satisfied
        - Consistent formatting across all calls
        """,
        evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
        model=judge_model,
        threshold=threshold,
        verbose_mode=False
    )


# ============================================================================
# Metric Suite
# ============================================================================


class InvestigationMetricSuite:
    """
    Runs 4 investigation GEval metrics and aggregates results.

    Metrics:
    1. Answer Quality - Always run
    2. Reasoning Quality - Only with tool calls
    3. Tool Selection Quality - Only with tool calls
    4. Tool Call Integrity - Only with tool calls

    Handles cases with and without tool_calls.
    """

    def __init__(self, judge_model: DeepEvalBaseLLM):
        if judge_model is None:
            raise ValueError("judge_model is required")

        self.judge_model = judge_model
        self.answer_quality = create_answer_quality_metric(judge_model)
        self.reasoning_quality = create_reasoning_quality_metric(judge_model)
        self.tool_selection = create_tool_selection_quality_metric(judge_model)
        self.tool_integrity = create_tool_call_integrity_metric(judge_model)

    def _format_trace(self, tool_calls: list[ToolCall]) -> str:
        """Format tool calls as readable trace (legacy method).

        Args:
            tool_calls: List of ToolCall objects from the extractor

        Returns:
            Formatted string representation of the investigation trace
        """
        if not tool_calls:
            return "[No tool calls recorded]"

        trace_parts = []
        for call in tool_calls:
            trace_parts.append(f"--- Step {call.step_id}: {call.tool_name} ---")
            if call.thought:
                trace_parts.append(f"Thought: {call.thought}")
            trace_parts.append(f"Action: {call.action or call.tool_name}")
            trace_parts.append(f"Action Input: {call.tool_input or call.action_input}")
            # Truncate long outputs
            output_preview = call.tool_output
            trace_parts.append(f"Observation: {output_preview}")
            trace_parts.append("")  # Empty line between steps
        return "\n".join(trace_parts)
    
    def _format_from_raw_spans(self, raw_spans: list[dict], format_type: str = "complete") -> str:
        """
        Format raw spans based on evaluation metric needs.
        
        Follows analyze_trace_eval.py logic to preserve complete information.
        
        Args:
            raw_spans: List of raw span dictionaries
            format_type: Type of formatting
                - "reasoning": For Reasoning Quality (thought + reason + observation)
                - "tool_selection": For Tool Selection (tool sequence)
                - "tool_integrity": For Tool Integrity (detailed tool calls)
                - "complete": For Answer Quality (full trace)
        
        Returns:
            Formatted string for the specific metric
        """
        if not raw_spans:
            return "[No investigation trace recorded]"
        
        if format_type == "reasoning":
            return self._format_for_reasoning_quality(raw_spans)
        elif format_type == "tool_selection":
            return self._format_for_tool_selection(raw_spans)
        elif format_type == "tool_integrity":
            return self._format_for_tool_integrity(raw_spans)
        else:
            return self._format_complete_trace(raw_spans)
    
    def _format_for_reasoning_quality(self, raw_spans: list[dict]) -> str:
        """
        Format for Reasoning Quality metric: focus on thought, reason, and observations.
        
        Shows the logical flow: What the agent thought, why, and what it found.
        """
        parts = []
        step_num = 1
        
        for span in raw_spans:
            fn = span["function_name"]
            
            if fn == "thought node":
                output_val = span.get("output_value", "")
                try:
                    thought_json = json.loads(output_val)
                    thought = thought_json.get("thought", "")
                    actions = thought_json.get("actions") or {}
                    reason = actions.get("reason", "")
                    tool = actions.get("tool", "")
                    
                    if thought:
                        parts.append(f"\n--- Step {step_num} ---")
                        parts.append(f"Thought: {thought}")
                        if reason:
                            parts.append(f"Reason: {reason}")
                        if tool:
                            parts.append(f"Planned Tool: {tool}")
                        step_num += 1
                except json.JSONDecodeError:
                    if output_val:
                        parts.append(f"\n--- Step {step_num} ---")
                        parts.append(f"Thought: {output_val}")
                        step_num += 1
            
            elif fn == "observation node":
                output_val = span.get("output_value", "")
                try:
                    obs_json = json.loads(output_val)
                    results = obs_json.get("results", [])
                    if results:
                        if isinstance(results, list):
                            preview = "\n".join(str(r) for r in results)
                        else:
                            preview = str(results)
                        parts.append(f"Observation: {preview}")
                except json.JSONDecodeError:
                    if output_val:
                        parts.append(f"Observation: {output_val}")
        
        return "\n".join(parts) if parts else "[No reasoning trace found]"
    
    def _format_tool_calls_for_selection(self, tool_calls: list[ToolCall]) -> str:
        """
        Format tool calls for Tool Selection Quality.
        
        Shows: Agent Thought + Selection Reason + Actual Tool Call (with arguments)
        """
        if not tool_calls:
            return "[No tool calls recorded]"
        
        parts = []
        for i, tc in enumerate(tool_calls, 1):
            parts.append("=" * 60)
            parts.append(f"Tool Call {i}")
            parts.append("=" * 60)
            
            # Parse thought and reason
            main_thought = ""
            reason = ""
            
            if tc.thought:
                if "Reason:" in tc.thought:
                    thought_parts = tc.thought.split("Reason:", 1)
                    main_thought = thought_parts[0].strip()
                    reason = thought_parts[1].strip()
                else:
                    main_thought = tc.thought.strip()
            
            # Format with clear labels
            if main_thought:
                parts.append(f'[Agent Thought]: "{main_thought}"')
            
            if reason:
                parts.append(f'[Selection Reason]: "{reason}"')
            
            # Combine tool name and arguments as a complete call
            if tc.tool_input:
                parts.append(f"[Actual Tool Call]: {tc.tool_name}({tc.tool_input})")
            else:
                parts.append(f"[Actual Tool Call]: {tc.tool_name}()")
            
            parts.append("")
        
        return "\n".join(parts)

    def _format_tool_calls_for_integrity(self, tool_calls: list[ToolCall]) -> str:
        """
        Format tool calls for integrity checking: syntax, required fields, output completeness.
        """
        if not tool_calls:
            return "[No tool calls recorded]"
        
        import ast
        
        parts = []
        for i, tc in enumerate(tool_calls, 1):
            parts.append("=" * 60)
            parts.append(f"Tool Call {i}")
            parts.append("=" * 60)
            
            # 1. Tool Name
            parts.append(f"[Tool Name]: {tc.tool_name}")
            
            # 2. Input Validation
            parts.append("\n[Input Parameters]:")
            if tc.tool_input:
                try:
                    # Handle both Python dict string {'key': 'val'} and JSON {"key": "val"}
                    if isinstance(tc.tool_input, str):
                        try:
                            parsed = ast.literal_eval(tc.tool_input)
                        except:
                            parsed = json.loads(tc.tool_input)
                    else:
                        parsed = tc.tool_input
                    
                    parts.append(f"  Format: Valid (type: {type(parsed).__name__})")
                    if isinstance(parsed, dict):
                        parts.append(f"  Fields: {list(parsed.keys())}")
                        parts.append(f"  Raw: {tc.tool_input}")
                    else:
                        parts.append(f"  Raw: {tc.tool_input}")
                except Exception as e:
                    parts.append(f"   Invalid format: {str(e)}")
                    parts.append(f"  Raw: {tc.tool_input}")
            else:
                parts.append("  Missing: No input parameters provided")
            
            # 3. Output Validation
            parts.append("\n[Tool Output]:")
            if tc.tool_output:
                output_lines = tc.tool_output.split('\n')
                parts.append(f"   Output received: {len(tc.tool_output)} chars, {len(output_lines)} lines")
                
                parts.append(f" Content:")
                for line in tc.tool_output.split('\n'):
                    parts.append(f"  {line}")
            else:
                parts.append(" Missing: No output recorded")
            
            parts.append("")
        
        return "\n".join(parts)
    
    def _format_complete_trace(self, raw_spans: list[dict]) -> str:
        """
        Format complete trace for Answer Quality: shows everything.
        
        Includes all thought nodes, observations, and tool calls.
        """
        parts = []
        
        for i, span in enumerate(raw_spans, 1):
            fn = span["function_name"]
            
            if fn == "thought node":
                output = span.get("output_value", "")
                parts.append(f"\n[Step {i}] THOUGHT:\n{output}")
            
            elif fn == "observation node":
                output = span.get("output_value", "")
                parts.append(f"\n[Step {i}] OBSERVATION:\n{output}")
            
            elif fn == "pre_process node":
                output = span.get("output_value", "")
                parts.append(f"\n[Step {i}] PRE_PROCESS:\n{output}")
            
            elif span["span_kind"] == "TOOL":
                tool_name = span.get("subspan_name") or fn
                output = span.get("output_value", "")
                parts.append(f"\n[Step {i}] TOOL ({tool_name}):\n{output}")
        
        return "\n".join(parts) if parts else "[No trace found]"

    def evaluate(self, input_data: InvestigationEvalInput) -> dict[str, Any]:
        """Run all applicable metrics with format optimized for each.

        Args:
            input_data: InvestigationEvalInput with checklist question, response, raw_spans, and tool calls

        Returns:
            Dictionary with evaluation results including scores and reasoning
        """
        results = {}
        has_investigation = input_data.has_raw_spans or input_data.has_tool_calls
        
        # Prefer raw_spans for formatting (more complete), fallback to tool_calls
        use_raw_spans = input_data.has_raw_spans

        # Always run Answer Quality
        if use_raw_spans:
            complete_trace = self._format_complete_trace(input_data.raw_spans)
            answer_output = f"{complete_trace}\n\n--- Final Response ---\n{input_data.final_response}"
        elif input_data.has_tool_calls:
            trace_str = self._format_trace(input_data.tool_calls)
            answer_output = f"{trace_str}\n\n--- Final Response ---\n{input_data.final_response}"
        else:
            answer_output = f"--- Final Response ---\n{input_data.final_response}"
        
        answer_test_case = LLMTestCase(input=input_data.checklist_question, actual_output=answer_output)
        # Add debug logging
        logger.debug("="*80)
        logger.debug("ANSWER QUALITY TEST CASE")
        logger.debug("="*80)
        logger.debug("Input: %s", answer_test_case.input)
        logger.debug("-"*80)
        logger.debug("Actual Output:\n%s", answer_test_case.actual_output)
        logger.debug("="*80)
        try:
            self.answer_quality.measure(answer_test_case)
            results["Answer Quality"] = {
                "score": self.answer_quality.score,
                "passed": self.answer_quality.score >= self.answer_quality.threshold,
                "reason": self.answer_quality.reason,
            }
        except Exception as e:
            results["Answer Quality"] = {"score": 0.0, "passed": False, "reason": f"Error: {e}"}

        # Run trace-dependent metrics if investigation trace available
        if has_investigation:
            # Reasoning Quality: needs thought + reason + observation
            if use_raw_spans:
                reasoning_output = self._format_from_raw_spans(input_data.raw_spans, "reasoning")
                reasoning_output += f"\n\n--- Final Response ---\n{input_data.final_response}"
            else:
                reasoning_output = answer_output
            
            reasoning_test_case = LLMTestCase(input=input_data.checklist_question, actual_output=reasoning_output)
            logger.debug("="*80)
            logger.debug("REASONING QUALITY TEST CASE")
            logger.debug("="*80)
            logger.debug("Input: %s", reasoning_test_case.input)
            logger.debug("-"*80)
            logger.debug("Actual Output:\n%s", reasoning_test_case.actual_output)
            logger.debug("="*80)
            
            try:
                self.reasoning_quality.measure(reasoning_test_case)
                results["Reasoning Quality"] = {
                    "score": self.reasoning_quality.score,
                    "passed": self.reasoning_quality.score >= self.reasoning_quality.threshold,
                    "reason": self.reasoning_quality.reason,
                }
            except Exception as e:
                results["Reasoning Quality"] = {"score": 0.0, "passed": False, "reason": f"Error: {e}"}
            
            # Tool Selection Quality: use tool_calls (already matched, no duplicates)
            if input_data.has_tool_calls:
                tool_selection_output = self._format_tool_calls_for_selection(input_data.tool_calls)
            else:
                tool_selection_output = "[No tool calls recorded]"
            
            tool_selection_test_case = LLMTestCase(input=input_data.checklist_question, actual_output=tool_selection_output)
            logger.debug("="*80)
            logger.debug("TOOL SELECTION QUALITY TEST CASE")
            logger.debug("="*80)
            logger.debug("Input: %s", tool_selection_test_case.input)
            logger.debug("-"*80)
            logger.debug("Actual Output:\n%s", tool_selection_test_case.actual_output)
            logger.debug("="*80)

            try:
                self.tool_selection.measure(tool_selection_test_case)
                results["Tool Selection Quality"] = {
                    "score": self.tool_selection.score,
                    "passed": self.tool_selection.score >= self.tool_selection.threshold,
                    "reason": self.tool_selection.reason,
                }
            except Exception as e:
                results["Tool Selection Quality"] = {"score": 0.0, "passed": False, "reason": f"Error: {e}"}
            
            # Tool Call Integrity: use tool_calls (already matched, no duplicates)
            if input_data.has_tool_calls:
                tool_integrity_output = self._format_tool_calls_for_integrity(input_data.tool_calls)
            else:
                tool_integrity_output = "[No tool calls recorded]"
            
            tool_integrity_test_case = LLMTestCase(input=input_data.checklist_question, actual_output=tool_integrity_output)
            logger.debug("="*80)
            logger.debug("TOOL CALL INTEGRITY TEST CASE")
            logger.debug("="*80)
            logger.debug("Input: %s", tool_integrity_test_case.input)
            logger.debug("-"*80)
            logger.debug("Actual Output:\n%s", tool_integrity_test_case.actual_output)
            logger.debug("="*80)

            try:
                self.tool_integrity.measure(tool_integrity_test_case)
                results["Tool Call Integrity"] = {
                    "score": self.tool_integrity.score,
                    "passed": self.tool_integrity.score >= self.tool_integrity.threshold,
                    "reason": self.tool_integrity.reason,
                }
            except Exception as e:
                results["Tool Call Integrity"] = {"score": 0.0, "passed": False, "reason": f"Error: {e}"}

        scores = [r["score"] for r in results.values()]
        overall_score = sum(scores) / len(scores) if scores else 0
        passed_count = sum(1 for r in results.values() if r["passed"])

        return {
            "overall_score": overall_score,
            "passed": passed_count == len(results),
            "passed_count": f"{passed_count}/{len(results)}",
            "individual_results": results,
            "cve_id": input_data.cve_id,
            "has_tool_calls": has_investigation,
            "num_tool_calls": len(input_data.tool_calls),
            "num_raw_spans": len(input_data.raw_spans)
        }
