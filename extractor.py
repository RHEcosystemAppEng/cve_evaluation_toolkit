#!/usr/bin/env python3
"""
完整测试：显示每个 question 的完整执行流程
thought → tool → observation 的完整链路
"""
import json

# ========== 读取数据 ==========
with open("raw_job_00587bc7.json", "r") as f:
    job_data = json.load(f)

with open("raw_traces_00587bc7.json", "r") as f:
    traces = json.load(f)

print("✅ 数据加载成功\n")

# ========== Helper functions ==========
def get_attr_str(attrs: dict, key: str) -> str:
    return attrs.get(key, {}).get("stringValue", "")

def safe_float(value, default=0.0):
    try:
        return float(value) if value else default
    except (ValueError, TypeError):
        return default

# ========== 从 job 获取 checklist questions ==========
analysis = job_data.get("jobOutput", {}).get("job_output", {}).get("analysis", [])
checklist_raw = analysis[0].get("checklist", []) if analysis else []

# ========== 收集 checklist_question spans ==========
checklist_spans = []
for trace in traces:
    attrs = trace.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
    metadata = trace.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
    
    func_name = get_attr_str(attrs, "nat.function.name")
    event_type = get_attr_str(attrs, "nat.event_type")
    
    if func_name == "checklist_question" and event_type == "FUNCTION_START":
        checklist_spans.append({
            "span_id": metadata.get("span_id", "")[:16],
            "start_time": get_attr_str(attrs, "nat.event_timestamp"),
        })

checklist_spans.sort(key=lambda s: safe_float(s.get("start_time")))

# ========== 收集所有 spans 并建立 parent 索引 ==========
NODE_FUNCTION_NAMES = {"thought node", "observation node", "pre_process node"}
all_spans = []
parent_to_children = {}

for trace in traces:
    attrs = trace.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
    metadata = trace.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
    
    func_name = get_attr_str(attrs, "nat.function.name")
    subspan_name = get_attr_str(attrs, "nat.subspan.name")
    event_type = get_attr_str(attrs, "nat.event_type")
    
    span_id = metadata.get("span_id", "")[:16]
    parent_span_id = metadata.get("parent_span_id", "")[:16]
    
    if func_name in NODE_FUNCTION_NAMES or event_type == "TOOL_START":
        span_data = {
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "function_name": subspan_name if event_type == "TOOL_START" else func_name,
            "subspan_name": subspan_name,
            "span_kind": "TOOL" if event_type == "TOOL_START" else "FUNCTION",
            "event_type": event_type,
            "input_value": get_attr_str(attrs, "input.value"),
            "output_value": get_attr_str(attrs, "output.value"),
            "start_time": get_attr_str(attrs, "nat.event_timestamp"),
        }
        all_spans.append(span_data)
        parent_to_children.setdefault(parent_span_id, []).append(span_data)

# ========== 递归收集子节点 ==========
def collect_descendants(parent_id, parent_to_children_map, depth=0, max_depth=5):
    if depth > max_depth:
        return []
    descendants = []
    direct_children = parent_to_children_map.get(parent_id, [])
    for child in direct_children:
        descendants.append(child)
        grandchildren = collect_descendants(child['span_id'], parent_to_children_map, depth+1, max_depth)
        descendants.extend(grandchildren)
    return descendants

# ========== 显示完整执行流程 ==========
print("=" * 120)
print("显示每个 Question 的完整执行流程")
print("=" * 120)

for i, checklist_item in enumerate(checklist_raw[:2], 1):  # 只显示前2个，避免输出过长
    question = checklist_item.get("input", "")
    response = checklist_item.get("response", "")
    
    print(f"\n{'='*120}")
    print(f"Question {i}:")
    print(f"{'='*120}")
    print(f"📝 Question: {question}")
    print(f"💬 Response: {response[:150]}...\n")
    
    if i-1 < len(checklist_spans):
        cq_span_id = checklist_spans[i-1]["span_id"]
        
        # 递归收集所有子孙节点
        all_descendants = collect_descendants(cq_span_id, parent_to_children)
        
        # 按时间排序
        sorted_descendants = sorted(all_descendants, key=lambda s: safe_float(s.get("start_time", 0)))
        
        # 过滤掉 pre_process nodes（不重要）
        important_spans = [s for s in sorted_descendants if s['function_name'] != 'pre_process node']
        
        print(f"   {'─'*116}")
        print(f"   完整执行流程 (共 {len(important_spans)} 个 spans):")
        print(f"   {'─'*116}\n")
        
        step_num = 1
        for j, span in enumerate(important_spans, 1):
            span_kind = span['span_kind']
            func_name = span['function_name']
            
            # 判断是完整版还是简化版 thought
            is_full_thought = (func_name == 'thought node' and len(span.get('output_value', '')) > 50)
            
            # 只显示完整版 thought、tools 和 observations
            if func_name == 'thought node' and not is_full_thought:
                continue  # 跳过简化版 thought
            
            print(f"   [{step_num:2d}] {span_kind:8} | {func_name:30}")
            
            if is_full_thought:
                # 完整版 thought node
                try:
                    output = json.loads(span.get('output_value', '{}'))
                    thought_text = output.get('thought', '')
                    actions = output.get('actions', {})
                    planned_tool = actions.get('tool', 'N/A')
                    reason = actions.get('reason', '')
                    mode = output.get('mode', '')
                    
                    print(f"        💭 Thought: {thought_text}")
                    print(f"        🎯 Planned Tool: {planned_tool}")
                    if reason:
                        print(f"        📝 Reason: {reason}")
                    print(f"        🔄 Mode: {mode}")
                except Exception as e:
                    print(f"        ⚠️  Parse error: {e}")
            
            elif span_kind == "TOOL":
                # Tool call
                tool_name = span['subspan_name']
                tool_input = span.get('input_value', '')
                tool_output = span.get('output_value', '')
                
                print(f"        🔧 Tool: {tool_name}")
                print(f"        📥 Input: {tool_input}")
                
                # 解析 output
                try:
                    output_json = json.loads(tool_output)
                    if 'content' in output_json:
                        content = output_json['content']
                        lines = content.split('\n')
                        print(f"        📤 Output (first 3 lines):")
                        for line in lines[:3]:
                            print(f"            {line}")
                        if len(lines) > 3:
                            print(f"            ... ({len(lines) - 3} more lines)")
                    else:
                        print(f"        📤 Output: {str(output_json)[:150]}...")
                except:
                    print(f"        📤 Output: {tool_output[:150]}...")
            
            elif func_name == "observation node":
                # Observation node
                obs_output_str = span.get('output_value', '{}')
                
                try:
                    output = json.loads(obs_output_str)
                    
                    if 'results' in output:
                        results = output['results']
                        if isinstance(results, list):
                            print(f"        👁️  Observation - Results ({len(results)} items):")
                            for idx, result in enumerate(results[:2], 1):
                                result_text = result[:100] if len(result) > 100 else result
                                print(f"            [{idx}] {result_text}{'...' if len(result) > 100 else ''}")
                            if len(results) > 2:
                                print(f"            ... and {len(results) - 2} more results")
                    
                    if 'memory' in output:
                        memory = output['memory']
                        if isinstance(memory, list) and len(memory) > 0:
                            print(f"        🧠 Memory ({len(memory)} items):")
                            for idx, mem in enumerate(memory[:2], 1):
                                print(f"            [{idx}] {mem}")
                            if len(memory) > 2:
                                print(f"            ... and {len(memory) - 2} more")
                except:
                    print(f"        👁️  Observation: {obs_output_str[:100]}...")
            
            print()
            step_num += 1

print("=" * 120)
print("\n✅ 完整执行流程显示完成！")
print(f"   如果前2个 questions 的流程正确，说明方案可行")
print("=" * 120)