"""
Orchestrator — wires Agents 1-5 into a single pipeline.
------------------------------------------------------
Uses LangGraph (the task document's preferred agent framework) if it's
installed. Falls back to a plain sequential Python pipeline otherwise —
functionally identical, just without the graph visualization/state-tracking
LangGraph provides. Either way, the actual agent logic is unchanged; this
file only controls the order they run in.

Run with:
    python orchestrator.py --base nist/csf --compare india/iso27001 --assess nist/csf
"""

import argparse

import agent2_knowledge_base as agent2
import agent3_control_mapping as agent3
import agent4_compliance_assessment as agent4
import agent5_report_generation as agent5


def run_pipeline_plain(base: str, compare: str, assess: str, explain_mappings: bool = False):
    """Sequential fallback — no LangGraph dependency required."""
    print("=== Agent 2: Knowledge Base ===")
    controls = agent2.load_all_controls()
    agent2.build_chroma_collection(controls)
    agent2.try_build_neo4j_graph(controls)

    print("\n=== Agent 3: Control Mapping ===")
    base_j, base_f = base.split("/")
    compare_j, compare_f = compare.split("/")
    mappings = agent3.map_controls(base_j, base_f, compare_j, compare_f, explain_mappings)
    print(f"Found {len(mappings)} mapping(s) between {base} and {compare}")

    print("\n=== Agent 4: Compliance Assessment ===")
    assess_j, assess_f = assess.split("/")
    assessment = agent4.assess_compliance(assess_j, assess_f)

    import os
    import json
    os.makedirs("assessments", exist_ok=True)
    with open(f"assessments/{assess_j}__{assess_f}_assessment.json", "w") as f:
        json.dump(assessment, f, indent=2)

    print("\n=== Agent 5: Report Generation ===")
    report = agent5.build_report(assess_j, assess_f, assessment, with_remediation=True)
    os.makedirs("reports", exist_ok=True)
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/{assess_j}__{assess_f}_report_{timestamp}.md"
    with open(report_path, "w") as f:
        f.write(report)

    print(f"\nPipeline complete. Final report -> {report_path}")
    return {"mappings": mappings, "assessment": assessment, "report_path": report_path}


def run_pipeline_langgraph(base: str, compare: str, assess: str, explain_mappings: bool = False):
    """LangGraph-based orchestration — same steps as run_pipeline_plain, expressed
    as a graph so you get state tracking / visualization for free."""
    from langgraph.graph import StateGraph, END
    from typing import TypedDict

    class PipelineState(TypedDict):
        base: str
        compare: str
        assess: str
        mappings: list
        assessment: list
        report_path: str

    def node_knowledge_base(state: PipelineState) -> PipelineState:
        controls = agent2.load_all_controls()
        agent2.build_chroma_collection(controls)
        agent2.try_build_neo4j_graph(controls)
        return state

    def node_control_mapping(state: PipelineState) -> PipelineState:
        base_j, base_f = state["base"].split("/")
        compare_j, compare_f = state["compare"].split("/")
        state["mappings"] = agent3.map_controls(base_j, base_f, compare_j, compare_f, explain_mappings)
        return state

    def node_compliance_assessment(state: PipelineState) -> PipelineState:
        assess_j, assess_f = state["assess"].split("/")
        state["assessment"] = agent4.assess_compliance(assess_j, assess_f)
        return state

    def node_report_generation(state: PipelineState) -> PipelineState:
        import os
        from datetime import datetime
        assess_j, assess_f = state["assess"].split("/")
        report = agent5.build_report(assess_j, assess_f, state["assessment"], with_remediation=True)
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"reports/{assess_j}__{assess_f}_report_{timestamp}.md"
        with open(report_path, "w") as f:
            f.write(report)
        state["report_path"] = report_path
        return state

    graph = StateGraph(PipelineState)
    graph.add_node("knowledge_base", node_knowledge_base)
    graph.add_node("control_mapping", node_control_mapping)
    graph.add_node("compliance_assessment", node_compliance_assessment)
    graph.add_node("report_generation", node_report_generation)

    graph.set_entry_point("knowledge_base")
    graph.add_edge("knowledge_base", "control_mapping")
    graph.add_edge("control_mapping", "compliance_assessment")
    graph.add_edge("compliance_assessment", "report_generation")
    graph.add_edge("report_generation", END)

    app = graph.compile()
    result = app.invoke({"base": base, "compare": compare, "assess": assess, "mappings": [], "assessment": [], "report_path": ""})
    print(f"\nPipeline complete. Final report -> {result['report_path']}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Full multi-agent compliance pipeline")
    parser.add_argument("--base", required=True, help="Base framework for mapping, e.g. nist/csf")
    parser.add_argument("--compare", required=True, help="Framework to compare against, e.g. india/iso27001")
    parser.add_argument("--assess", required=True, help="Framework to assess compliance for, e.g. nist/csf")
    parser.add_argument("--explain", action="store_true", help="Add LLM explanations to mappings (slower)")
    args = parser.parse_args()

    try:
        import langgraph  # noqa: F401
        print("LangGraph found — using graph-based orchestration.\n")
        run_pipeline_langgraph(args.base, args.compare, args.assess, args.explain)
    except ImportError:
        print("LangGraph not installed — using plain sequential orchestration "
              "(functionally identical). Run `pip install langgraph` to enable graph mode.\n")
        run_pipeline_plain(args.base, args.compare, args.assess, args.explain)


if __name__ == "__main__":
    main()
