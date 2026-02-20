"""
Agent Investigation Evaluation Metrics.

4 GEval metrics for evaluating ReAct agent CVE investigation:
1. Answer Quality - Relevancy + Evidence support
2. Reasoning Quality - Logic coherence + Goal focus
3. Tool Selection Quality - Semantic appropriateness (no syntax)
4. Tool Call Integrity - Syntax and schema validation
"""

from typing import Any

from deepeval.metrics import GEval
from deepeval.models.base_model import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase
from deepeval.test_case import LLMTestCaseParams
from pydantic import BaseModel
from pydantic import Field

from evaluation.extractors.data_extractor import ToolCall

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
    """

    cve_id: str = Field(description="CVE identifier")
    checklist_question: str = Field(description="The checklist question being investigated")
    final_response: str = Field(default="", description="Agent's final response for this question")
    tool_calls: list[ToolCall] = Field(default_factory=list, description="All tool calls made for this step")

    @property
    def has_tool_calls(self) -> bool:
        """Check if this investigation has tool calls."""
        return len(self.tool_calls) > 0

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
                   tool_calls=step_detail.tool_calls)


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

        B. EVIDENCE SUPPORT (50% weight):
        - Is the answer backed by evidence from tool outputs?
        - Are specific citations provided (files, functions, line numbers)?
        - Were multiple sources consulted to verify findings?
        - Did the agent try alternative queries when searches failed?
        - Are limitations/uncertainties acknowledged?

        SCORING RUBRIC:

        Score 0.0-0.2 (FAIL):
        - Answer doesn't address the question OR
        - No evidence provided, claims made without verification
        - "I don't know" without investigation attempt

        Score 0.3-0.4 (POOR):
        - Answer tangentially related to question
        - Single source only, no verification
        - Vague claims without specific citations

        Score 0.5-0.6 (ADEQUATE):
        - Answer addresses question but incompletely
        - Some evidence provided, basic citations
        - At least 2 sources consulted

        Score 0.7-0.8 (GOOD):
        - Answer clearly addresses the question
        - Multiple sources triangulated
        - Specific citations (file paths, function names)
        - Evidence clearly supports conclusion

        Score 0.9-1.0 (EXCELLENT):
        - Answer thoroughly and specifically addresses question
        - Comprehensive evidence from multiple tools
        - Verified findings from multiple angles
        - Specific, traceable citations throughout
        - Clear distinction between confirmed facts and inferences
        - Acknowledges limitations where appropriate
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold)


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
        ACTUAL OUTPUT: The agent's reasoning trace (Thought → Action → Observation loops)

        NOTE: If no intermediate steps are present, score based on whether the
        final answer shows logical reasoning and stays focused on the question.

        In your reasoning, explicitly reference the specific requirements of this criteria. Use the format: 'The response [meets/fails] the [Specific Criteria Name] because [Evidence from Output], which directly relates to the requirement of [Specific Clause from Criteria].

        EVALUATION DIMENSIONS:

        A. LOGICAL COHERENCE (50% weight):
        - Does each Thought logically follow from the previous Observation?
        - Are tool selections justified by the reasoning?
        - Are there contradictions or circular reasoning?
        - Does the conclusion follow from the evidence?

        B. GOAL FOCUS (50% weight):
        - Does each step progress toward answering the question?
        - Are there unnecessary tangents or distractions?
        - Does the agent stay on topic throughout?
        - Is the final answer focused on the original question?

        SCORING RUBRIC:

        Score 0.0-0.2 (FAIL):
        - Incoherent reasoning: contradictions, circular logic
        - Completely off-topic investigation
        - Conclusion contradicts evidence found

        Score 0.3-0.4 (POOR):
        - Major logic gaps: unexplained jumps in reasoning
        - More than half of steps are tangential
        - Tool selections don't match stated goals

        Score 0.5-0.6 (ADEQUATE):
        - Generally logical with minor gaps
        - Some tangents but mostly on topic
        - Conclusions mostly follow from evidence

        Score 0.7-0.8 (GOOD):
        - Each Thought logically follows Observation
        - All steps progress toward the answer
        - Tool selections are justified
        - No contradictions in reasoning

        Score 0.9-1.0 (EXCELLENT):
        - Perfect logical chain from question to answer
        - Every step directly contributes to the goal
        - Tool selections explicitly justified
        - Efficient, focused investigation
        - Considers multiple angles before concluding
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold)


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
        - Was each tool the right choice for its query?
        - Semantic Search for "how does X work?" questions
        - Keyword Search for specific names/patterns
        - CVE Web Search for external exploit/patch info
        - Function Locator for finding where code is defined

        2. TOOL SEQUENCE AND DEPENDENCIES (40% weight):
        - Function Locator MUST precede Call Chain Analyzer (dependency!)
        - Function Locator MUST precede Function Caller Finder (dependency!)
        - Broad searches (semantic) before narrow analysis (function-level)
        - Logical progression: understand → locate → trace → verify

        GOOD sequence example:
          Step 1: Function Locator (find the function)
          Step 2: Call Chain Analyzer (trace how it's called)
          Step 3: Code Keyword Search (verify usage context)

        BAD sequence example:
          Step 1: Call Chain Analyzer (ERROR: no function located yet!)
          Step 2: Function Locator (should have been first)

        3. SEMANTIC INPUT CORRECTNESS (20% weight):
        - Is the input the RIGHT thing to search for?
        - Does the query target what the question asks?
        - Are function/package names relevant to the CVE?
        - Example BAD: Question asks about "werkzeug", but searches for "flask"

        IMPORTANT: Do NOT penalize for syntax errors (wrong format, missing fields).
        That is evaluated separately by Tool Call Integrity metric.

        SCORING RUBRIC:

        Score 0.0-0.3 (FAIL):
        - Wrong tools for the task (semantic mismatch)
        - Violates dependencies (Call Chain before Locator)
        - Searches for completely irrelevant things

        Score 0.4-0.6 (ADEQUATE):
        - Mostly appropriate tools but suboptimal sequence
        - Some queries miss the point but not completely wrong
        - Basic understanding but inefficient approach

        Score 0.7-0.8 (GOOD):
        - Correct tool choices with proper dependencies
        - Semantically appropriate queries
        - Logical sequence that builds on previous findings

        Score 0.9-1.0 (EXCELLENT):
        - Optimal tool selection for each step
        - Perfect dependency ordering
        - Queries precisely target what's needed
        - Efficient investigation path
        """,
                 evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT],
                 model=judge_model,
                 threshold=threshold)


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
        threshold=threshold
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
        """Format tool calls as readable trace.

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
            output_preview = call.tool_output[:800] + "..." if len(call.tool_output) > 800 else call.tool_output
            trace_parts.append(f"Observation: {output_preview}")
            trace_parts.append("")  # Empty line between steps
        return "\n".join(trace_parts)

    def evaluate(self, input_data: InvestigationEvalInput) -> dict[str, Any]:
        """Run all applicable metrics.

        Args:
            input_data: InvestigationEvalInput with checklist question, response, and tool calls

        Returns:
            Dictionary with evaluation results including scores and reasoning
        """
        results = {}
        has_tool_calls = input_data.has_tool_calls

        # Build the full output string for evaluation
        if has_tool_calls:
            trace_str = self._format_trace(input_data.tool_calls)
            full_output = f"{trace_str}\n\n--- Final Response ---\n{input_data.final_response}"
        else:
            full_output = f"--- Final Response ---\n{input_data.final_response}"

        test_case = LLMTestCase(input=input_data.checklist_question, actual_output=full_output)

        # Always run Answer Quality
        metrics_to_run = [("Answer Quality", self.answer_quality)]

        # Run trace-dependent metrics if tool calls available
        if has_tool_calls:
            metrics_to_run.extend([
                ("Reasoning Quality", self.reasoning_quality),
                ("Tool Selection Quality", self.tool_selection),
                ("Tool Call Integrity", self.tool_integrity),
            ])

        for name, metric in metrics_to_run:
            try:
                metric.measure(test_case)
                results[name] = {
                    "score": metric.score,
                    "passed": metric.score >= metric.threshold,
                    "reason": metric.reason,
                }
            except Exception as e:
                results[name] = {"score": 0.0, "passed": False, "reason": f"Error: {e}"}

        scores = [r["score"] for r in results.values()]
        overall_score = sum(scores) / len(scores) if scores else 0
        passed_count = sum(1 for r in results.values() if r["passed"])

        return {
            "overall_score": overall_score,
            "passed": passed_count == len(results),
            "passed_count": f"{passed_count}/{len(results)}",
            "individual_results": results,
            "cve_id": input_data.cve_id,
            "has_tool_calls": has_tool_calls,
            "num_tool_calls": len(input_data.tool_calls)
        }
