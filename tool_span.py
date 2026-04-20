#!/usr/bin/env python3
"""
调试 Code Keyword Search 提取问题
"""
import json

# 读取 traces
with open("raw_traces_00587bc7.json", "r") as f:
    traces = json.load(f)

def get_attr_str(attrs: dict, key: str) -> str:
    """提取 attributes 中的字符串值"""
    return attrs.get(key, {}).get("stringValue", "")

def safe_float(value, default=0.0):
    """安全地转换为 float"""
    try:
        return float(value) if value else default
    except (ValueError, TypeError):
        return default

# 收集所有相关的 spans
NODE_FUNCTION_NAMES = {"thought node", "observation node", "pre_process node"}
agent_spans = []

for trace in traces:
    attrs = trace.get("spanPayload", {}).get("span_payload", {}).get("attributes", {})
    metadata = trace.get("spanPayload", {}).get("span_payload", {}).get("metadata", {})
    
    func_name = get_attr_str(attrs, "nat.function.name")
    subspan_name = get_attr_str(attrs, "nat.subspan.name")
    event_type = get_attr_str(attrs, "nat.event_type")
    
    # 检查是否是 NODE_FUNCTION_NAMES
    if func_name in NODE_FUNCTION_NAMES:
        span_data = {
            "span_id": metadata.get("span_id", "")[:16],
            "parent_span_id": metadata.get("parent_span_id", "")[:16],
            "function_name": func_name,
            "subspan_name": subspan_name,
            "span_kind": "FUNCTION",
            "event_type": event_type,
            "input_value": get_attr_str(attrs, "input.value")[:200],
            "output_value": get_attr_str(attrs, "output.value")[:300],
            "start_time": get_attr_str(attrs, "nat.event_timestamp"),
        }
        agent_spans.append(span_data)
    
    # 检查是否是 TOOL_START
    elif event_type == "TOOL_START":
        span_data = {
            "span_id": metadata.get("span_id", "")[:16],
            "parent_span_id": metadata.get("parent_span_id", "")[:16],
            "function_name": subspan_name or func_name,
            "subspan_name": subspan_name,
            "span_kind": "TOOL",
            "event_type": event_type,
            "input_value": get_attr_str(attrs, "input.value")[:200],
            "output_value": get_attr_str(attrs, "output.value")[:300],
            "start_time": get_attr_str(attrs, "nat.event_timestamp"),
        }
        agent_spans.append(span_data)

# 按时间排序（安全处理空值）
agent_spans.sort(key=lambda s: safe_float(s.get("start_time")))

print(f"✅ 总共收集到 {len(agent_spans)} 个相关 spans\n")
print("=" * 120)

# 统计
tool_count = sum(1 for s in agent_spans if s['span_kind'] == "TOOL")
thought_count = sum(1 for s in agent_spans if s['function_name'] == "thought node")
observation_count = sum(1 for s in agent_spans if s['function_name'] == "observation node")

print(f"\n📊 统计:")
print(f"  - Thought nodes: {thought_count}")
print(f"  - Observation nodes: {observation_count}")
print(f"  - Tool calls: {tool_count}")
print()

# 显示前 30 个 spans（覆盖第一个 checklist question）
print("=" * 120)
print("\n🔎 前 30 个 spans (按时间顺序):\n")

for i, span in enumerate(agent_spans[:30], 1):
    timestamp = safe_float(span['start_time'])
    print(f"[{i:2d}] {span['span_kind']:8} | {span['function_name']:30} | time={timestamp:.2f}")
    
    if span['function_name'] == "thought node":
        # 解析 thought 的 output
        try:
            output = json.loads(span.get('output_value', '{}'))
            thought_text = output.get('thought', '')[:70]
            actions = output.get('actions', {})
            planned_tool = actions.get('tool', 'N/A')
            reason = actions.get('reason', '')[:60]
            print(f"     💭 Thought: {thought_text}...")
            print(f"     🎯 Planned Tool: {planned_tool}")
            if reason:
                print(f"     📝 Reason: {reason}...")
        except Exception as e:
            print(f"     ⚠️  Cannot parse output: {e}")
    
    elif span['span_kind'] == "TOOL":
        print(f"     🔧 Tool: {span['subspan_name']}")
        print(f"     📥 Input: {span.get('input_value', '')[:80]}...")
        output_preview = span.get('output_value', '')[:80]
        print(f"     📤 Output: {output_preview}...")
    
    elif span['function_name'] == "observation node":
        output_preview = span.get('output_value', '')[:80]
        print(f"     👁️  Observation: {output_preview}...")
    
    print()

print("=" * 120)

# 查找所有 "Code Keyword Search" 相关的 spans
print("\n🔍 所有 'Code Keyword Search' 相关的 spans:\n")
code_search_spans = [s for s in agent_spans if "Code Keyword Search" in s.get('subspan_name', '') or 
                                                 "Code Keyword Search" in s.get('function_name', '')]
print(f"找到 {len(code_search_spans)} 个 'Code Keyword Search' spans\n")

for i, span in enumerate(code_search_spans, 1):
    print(f"[{i}] {span['span_kind']:8} | span_id={span['span_id']} | parent={span['parent_span_id']}")
    print(f"    Input: {span.get('input_value', '')[:100]}")
    print(f"    Output (preview): {span.get('output_value', '')[:100]}...")
    print()

print("=" * 120)

# 额外：检查 parent_span_id 对应关系
print("\n🔗 检查 'Code Keyword Search' 的 parent span:\n")
for code_span in code_search_spans:
    parent_id = code_span['parent_span_id']
    parent_span = next((s for s in agent_spans if s['span_id'] == parent_id), None)
    
    if parent_span:
        print(f"Code Keyword Search (span_id={code_span['span_id']})")
        print(f"  └─ Parent: {parent_span['function_name']} (span_id={parent_id})")
        if parent_span['function_name'] == "thought node":
            try:
                output = json.loads(parent_span.get('output_value', '{}'))
                thought = output.get('thought', '')[:60]
                print(f"     Thought: {thought}...")
            except:
                pass
    else:
        print(f"⚠️  Code Keyword Search parent not found: {parent_id}")
    print()