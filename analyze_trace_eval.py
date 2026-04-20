import json
import re
from collections import defaultdict

# ============================================================================
# read data
# ============================================================================

with open("raw_job_00587bc7.json", "r") as f:
    job = json.load(f)

with open("raw_traces_00587bc7.json", "r") as f:
    spans = json.load(f)

# extract 5 checklist questions
checklist = job.get("jobOutput", {}).get("job_output", {}).get("analysis", [{}])[0].get("checklist", [])
checklist_questions = [item.get('input', '') for item in checklist]

print(f"Job has {len(checklist_questions)} checklist questions")
print("="*100 + "\n")

# ============================================================================
# Helper functions
# ============================================================================

def get_attr_str(attrs, key):
    return attrs.get(key, {}).get("stringValue", "")

def extract_question_from_llm_input(input_value: str) -> str:
    """Extract question from thought node's LLM input."""
    try:
        messages = json.loads(input_value)
        for msg in messages:
            if isinstance(msg, dict) and msg.get("type") == "human":
                content = msg.get("content", "")
                # extract things in between INVESTIGATION_QUESTION 
                if "<INVESTIGATION_QUESTION>" in content:
                    start = content.find("<INVESTIGATION_QUESTION>") + len("<INVESTIGATION_QUESTION>")
                    end = content.find("</INVESTIGATION_QUESTION>")
                    if end > start:
                        return content[start:end].strip()
                return content
    except:
        pass
    return ""

def normalize_question(q: str) -> str:
    """Normalize question for matching (lowercase, remove extra spaces)."""
    return " ".join(q.lower().split())[:100]

# ============================================================================
# collect all thought/observation/tool spans
# ============================================================================

NODE_NAMES = {"thought node", "observation node", "pre_process node"}

agent_spans = []
for span in spans:
    attrs = span.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
    metadata = span.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
    
    fn = get_attr_str(attrs, "nat.function.name")
    subspan = get_attr_str(attrs, "nat.subspan.name")
    event_type = get_attr_str(attrs, "nat.event_type")
    
    if fn in NODE_NAMES or event_type == "TOOL_START":
        span_data = {
            "span_id": span.get("span_id", "")[:16],
            "parent_span_id": metadata.get("parent_span_id", "")[:16],
            "function_name": fn,
            "subspan_name": subspan,
            "span_kind": "FUNCTION" if fn in NODE_NAMES else "TOOL",
            "input_value": get_attr_str(attrs, "input.value"),
            "output_value": get_attr_str(attrs, "output.value"),
            "start_time": get_attr_str(attrs, "nat.event_timestamp"),
            "token_prompt": attrs.get("llm.token_count.prompt", {}).get("intValue", 0),
            "token_completion": attrs.get("llm.token_count.completion", {}).get("intValue", 0),
        }
        agent_spans.append(span_data)

# sort by time
agent_spans.sort(key=lambda s: s.get("start_time", ""))

print(f"Found {len(agent_spans)} agent spans\n")

# ============================================================================
# group by questions with content not parent_span_id
# ============================================================================

# build normalized checklist questions index
normalized_checklist = {normalize_question(q): q for q in checklist_questions}

print("Checklist questions (normalized):")
for i, (norm_q, orig_q) in enumerate(normalized_checklist.items(), 1):
    print(f"{i}. {norm_q[:200]}...")
print("\n" + "="*100 + "\n")

# put every span to according checklist question
question_to_spans = defaultdict(list)
current_question = None

for span in agent_spans:
    # if thought node，extract question update current_question
    if span["function_name"] == "thought node":
        extracted_q = extract_question_from_llm_input(span.get("input_value", ""))
        if extracted_q:
            norm_extracted = normalize_question(extracted_q)
            
            # try match checklist questions
            matched = None
            for norm_checklist_q, orig_checklist_q in normalized_checklist.items():
                # match first 60 char
                if norm_extracted[:200] in norm_checklist_q or norm_checklist_q[:200] in norm_extracted:
                    matched = orig_checklist_q
                    break
            
            if matched:
                current_question = matched
                question_to_spans[matched].append(span)
            else:
                # if not match, save as individual question
                question_to_spans[extracted_q].append(span)
                current_question = extracted_q
    else:
        # observation / tool spans follow recent thought question
        if current_question:
            question_to_spans[current_question].append(span)

# ============================================================================
# show question investigation
# ============================================================================

print(f"TOTAL UNIQUE QUESTIONS FOUND: {len(question_to_spans)}")
print("="*100 + "\n\n")

for flow_idx, (question, spans) in enumerate(question_to_spans.items(), 1):
    print("="*100)
    print(f"FLOW {flow_idx}/{len(question_to_spans)}")
    print("="*100)
    print(f"Question: {question[:300]}...")
    print(f"Total spans: {len(spans)}")
    
    # calc
    thought_count = sum(1 for s in spans if s['function_name'] == 'thought node')
    observation_count = sum(1 for s in spans if s['function_name'] == 'observation node')
    tool_count = sum(1 for s in spans if s['span_kind'] == 'TOOL')
    
    print(f"Stats: {thought_count} thoughts, {observation_count} observations, {tool_count} tools")
    print()
    
    # first 10 steps
    print("First 10 steps:")
    print("-"*100)
    for i, span in enumerate(spans[:10], 1):
        fn = span['function_name']
        subspan = span['subspan_name']
        if fn == "thought node":
            print(f"  {i}. THOUGHT: {span.get('output_value', '')[:600]}...")
        elif fn == "observation node":
            print(f"  {i}. OBSERVATION: {span.get('output_value', '')[:600]}...")
        elif fn == "pre_process node":
            print(f"  {i}. PRE_PROCESS: {span.get('output_value', '')[:600]}...")
        else:
            print(f"  {i}. TOOL ({subspan}): {span.get('output_value', '')[:600]}...")
    
    if len(spans) > 10:
        print(f"  ... and {len(spans) - 10} more steps")
    
    print("\n" + "="*100 + "\n\n")

# ============================================================================
# match summary
# ============================================================================

print("="*100)
print("MATCHING SUMMARY")
print("="*100 + "\n")

matched_count = 0
for checklist_q in checklist_questions:
    if checklist_q in question_to_spans:
        matched_count += 1
        spans_count = len(question_to_spans[checklist_q])
        print(f" Matched: {checklist_q[:100]}... ({spans_count} spans)")
    else:
        print(f" NOT FOUND: {checklist_q[:100]}...")

print(f"\n{matched_count}/{len(checklist_questions)} checklist questions matched")

# import json
# import re
# from collections import defaultdict

# # ============================================================================
# # read data
# # ============================================================================

# with open("raw_job_00587bc7.json", "r") as f:
#     job = json.load(f)

# with open("raw_traces_00587bc7.json", "r") as f:
#     spans = json.load(f)

# # extract 5 checklist questions
# checklist = job.get("jobOutput", {}).get("job_output", {}).get("analysis", [{}])[0].get("checklist", [])
# print(f"Job has {len(checklist)} checklist questions\n")
# print("="*100)

# checklist_questions = []
# for i, item in enumerate(checklist, 1):
#     q = item.get('input', '')
#     checklist_questions.append(q)
#     print(f"Q{i}: {q[:150]}...")
#     print()

# print("="*100 + "\n\n")

# # ============================================================================
# # Helper functions
# # ============================================================================

# def get_attr_str(attrs, key):
#     return attrs.get(key, {}).get("stringValue", "")

# def extract_question_from_llm_input(input_value: str) -> str:
#     """Extract question from thought node's LLM input (human message)."""
#     try:
#         messages = json.loads(input_value)
#         for msg in messages:
#             if isinstance(msg, dict) and msg.get("type") == "human":
#                 return msg.get("content", "")
#     except:
#         pass
#     return ""

# def classify_llm_span(output_value: str) -> str:
#     """'thought' if output starts with {"thought, else 'observation'."""
#     stripped = output_value.lstrip()
#     if stripped.startswith('{"thought"'):
#         return "thought"
#     return "observation"

# def extract_thought_mode(output: str) -> str:
#     """Extract 'act' or 'finish' from thought output."""
#     try:
#         parsed = json.loads(output)
#         return parsed.get("mode", "")
#     except:
#         pass
#     m = re.search(r'"mode"\s*:\s*"(act|finish)"', output)
#     return m.group(1) if m else ""

# def extract_goal_from_observation_input(input_value: str) -> str:
#     """Extract GOAL question from observation node input."""
#     try:
#         messages = json.loads(input_value)
#         for msg in messages:
#             content = msg.get("content", "") if isinstance(msg, dict) else ""
#             if "GOAL:" in content:
#                 goal_line = content.split("GOAL:")[1].split("\n")[0].strip()
#                 return goal_line[:150]
#     except:
#         pass
#     return ""

# # ============================================================================
# # collect agent spans
# # ============================================================================

# NODE_NAMES = {"thought node", "observation node", "pre_process node", "forced_finish node"}

# agent_spans = []
# for span in spans:
#     attrs = span.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
#     metadata = span.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
    
#     fn = get_attr_str(attrs, "nat.function.name")
#     event_type = get_attr_str(attrs, "nat.event_type")
    
#     # collect node functions & TOOL spans
#     if fn in NODE_NAMES or event_type == "TOOL_START":
#         span_data = {
#             "span_id": span.get("span_id", "")[:16],
#             "parent_span_id": metadata.get("parent_span_id", "")[:16],
#             "function_name": fn,
#             "span_kind": "FUNCTION" if fn in NODE_NAMES else "TOOL",
#             "event_type": event_type,
#             "input_value": get_attr_str(attrs, "input.value"),
#             "output_value": get_attr_str(attrs, "output.value"),
#             "start_time": get_attr_str(attrs, "nat.event_timestamp"),
#             "token_prompt": attrs.get("llm.token_count.prompt", {}).get("intValue", 0),
#             "token_completion": attrs.get("llm.token_count.completion", {}).get("intValue", 0),
#         }
#         agent_spans.append(span_data)

# # by time
# agent_spans.sort(key=lambda s: s.get("start_time", ""))

# print(f"Found {len(agent_spans)} agent spans (thoughts, observations, tools)\n")

# # ============================================================================
# # 分组：按 parent_span_id 分组，然后在组内按 question 再分
# # ============================================================================

# parent_groups = defaultdict(list)
# for span in agent_spans:
#     parent_groups[span["parent_span_id"]].append(span)

# print(f"Grouped into {len(parent_groups)} parent_span_id groups\n")
# print("="*100 + "\n")

# # 对每个 parent group，按 question 再分组
# all_flows = []
# for parent_id, group_spans in parent_groups.items():
#     # 按时间排序
#     group_spans.sort(key=lambda s: s.get("start_time", ""))
    
#     # 找出所有出现的 questions (从 thought node 提取)
#     questions_seen = []
#     for span in group_spans:
#         if span["function_name"] == "thought node":
#             q = extract_question_from_llm_input(span.get("input_value", ""))
#             if q and q not in questions_seen:
#                 questions_seen.append(q)
    
#     # 如果有多个 questions，分组
#     if len(questions_seen) > 1:
#         question_groups = {q: [] for q in questions_seen}
#         last_thought_question = None
        
#         for span in group_spans:
#             if span["function_name"] == "thought node":
#                 q = extract_question_from_llm_input(span.get("input_value", ""))
#                 if q in question_groups:
#                     last_thought_question = q
#                     question_groups[q].append(span)
            
#             elif span["function_name"] == "observation node":
#                 # observation 跟随最近的 thought
#                 if last_thought_question:
#                     question_groups[last_thought_question].append(span)
            
#             elif span["span_kind"] in ("FUNCTION", "TOOL"):
#                 # 其他 FUNCTION/TOOL spans 也跟随
#                 if last_thought_question:
#                     question_groups[last_thought_question].append(span)
        
#         for q_text, q_spans in question_groups.items():
#             if q_spans:
#                 all_flows.append({
#                     "parent_id": parent_id,
#                     "question": q_text,
#                     "spans": q_spans
#                 })
#     else:
#         # 单个 question 或无法分割
#         q_text = questions_seen[0] if questions_seen else ""
#         if group_spans:
#             all_flows.append({
#                 "parent_id": parent_id,
#                 "question": q_text,
#                 "spans": group_spans
#             })

# print(f"TOTAL FLOWS FOUND: {len(all_flows)}\n")
# print("="*100 + "\n\n")

# # ============================================================================
# # 逐个 flow 显示详细的 investigation steps
# # ============================================================================

# for flow_idx, flow in enumerate(all_flows, 1):
#     print("="*100)
#     print(f"FLOW {flow_idx}/{len(all_flows)}")
#     print("="*100)
#     print(f"Parent ID: {flow['parent_id']}")
#     print(f"Question: {flow['question'][:200]}...")
#     print(f"Total spans: {len(flow['spans'])}")
#     print()
    
#     # 构建详细的 step 序列
#     print("STEP SEQUENCE:")
#     print("-"*100)
    
#     for step_num, span in enumerate(flow['spans'], 1):
#         fn = span['function_name']
#         kind = span['span_kind']
        
#         if fn == "thought node":
#             mode = extract_thought_mode(span.get('output_value', ''))
#             print(f"\n[Step {step_num}] THOUGHT (mode={mode})")
#             print(f"  Input (first 150 chars): {span.get('input_value', '')[:150]}...")
#             print(f"  Output (first 150 chars): {span.get('output_value', '')[:150]}...")
#             print(f"  Tokens: prompt={span['token_prompt']}, completion={span['token_completion']}")
        
#         elif fn == "observation node":
#             print(f"\n[Step {step_num}] OBSERVATION")
#             print(f"  Output (first 200 chars): {span.get('output_value', '')[:200]}...")
#             print(f"  Tokens: prompt={span['token_prompt']}, completion={span['token_completion']}")
        
#         elif fn == "pre_process node":
#             print(f"\n[Step {step_num}] PRE_PROCESS")
#             print(f"  Output (first 150 chars): {span.get('output_value', '')[:150]}...")
        
#         elif kind == "TOOL":
#             print(f"\n[Step {step_num}] TOOL: {fn}")
#             print(f"  Input (first 100 chars): {span.get('input_value', '')[:100]}...")
#             print(f"  Output (first 100 chars): {span.get('output_value', '')[:100]}...")
    
#     print("\n" + "="*100 + "\n\n")

# # ============================================================================
# # 匹配 checklist questions
# # ============================================================================

# print("="*100)
# print("MATCHING CHECKLIST QUESTIONS TO FLOWS")
# print("="*100 + "\n")

# for i, checklist_q in enumerate(checklist_questions, 1):
#     print(f"Checklist Q{i}: {checklist_q[:100]}...")
    
#     # 找匹配的 flows (使用前 60 个字符匹配)
#     matched_flows = []
#     for flow_idx, flow in enumerate(all_flows, 1):
#         flow_q = flow['question']
#         if flow_q and (checklist_q[:60] in flow_q or flow_q[:60] in checklist_q):
#             matched_flows.append(flow_idx)
    
#     if matched_flows:
#         print(f"  → Matched to Flow(s): {matched_flows}")
#         print(f"     Total steps: {sum(len(all_flows[idx-1]['spans']) for idx in matched_flows)}")
#     else:
#         print(f"  → NO MATCH FOUND!")
    
#     print()