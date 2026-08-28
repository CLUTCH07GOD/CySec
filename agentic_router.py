"""
Master Agentic Multi-Agent StateGraph Architecture
--------------------------------------------------
Fully converts all agents (Agents 0-7, Agent X/Y/Z, Onboarding Engine) into an
autonomous, state-driven multi-agent network powered by LangGraph and LangChain.

Capabilities:
1. Dynamic Intent & Parameter Classification (Supervisor Node)
2. Ingestion & Indexing Node (Agents 1, 1B & 2)
3. Framework Mapping Node (Agent 3)
4. Compliance Assessment & Reporting Node (Agents 4 & 5)
5. Dynamic Security Verification & Probing Node (Agents X, Y & Z)
6. Training Data Synthesis & LoRA Adapter Fine-Tuning Node (Agents 6 & 7) [Human-in-the-loop Gate]
7. Enterprise Onboarding & Client Policy Generation Node (Onboarding Engine)
8. Conversational RAG & Decision Node (LangChain Local Model Pipeline)
"""

import os
import sys
import re
import json
from typing import TypedDict, Optional, List, Dict, Any
from langgraph.graph import StateGraph, END

# Ensure local imports work
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

for sub in ["database", "governance", "utils", "ingestion", "evaluation", "agents"]:
    p = os.path.join(PROJECT_ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

import agents.config as agent_config
import agents.agent0_master_orchestrator as agent0_master
import agents.agent1_ingestion as agent1
import agents.agent1b_code_ingestion as agent1b
import agents.agent2_knowledge_base as agent2
import agents.agent3_control_mapping as agent3
import agents.agent4_compliance_assessment as agent4
import agents.agent5_report_generation as agent5
import agents.agent6_data_synthesis as agent6
import agents.agent7_lora_trainer as agent7

# Try importing optional dynamic probing agents safely
try:
    import agents.agent_x_discovery as agent_x
    import agents.agent_y_dynamic_probes as agent_y
    import agents.agent_z_verification_orchestrator as agent_z
    PROBING_AGENTS_AVAILABLE = True
except ImportError:
    PROBING_AGENTS_AVAILABLE = False

try:
    import agents.client_onboarding_engine as onboarding_engine
    ONBOARDING_AVAILABLE = True
except ImportError:
    ONBOARDING_AVAILABLE = False

# Comprehensive dynamic framework dictionary mapping all aliases to (jurisdiction, framework_key)
KNOWN_FRAMEWORKS = {
    # GDPR
    "gdpr": ("eu", "gdpr"),
    "eu_gdpr": ("eu", "gdpr"),
    "eu gdpr": ("eu", "gdpr"),
    # NIS2
    "nis2": ("eu", "nis2"),
    "eu_nis2": ("eu", "nis2"),
    "eu nis2": ("eu", "nis2"),
    # DPDP / DPD
    "dpdp": ("india", "dpdp"),
    "dpd": ("india", "dpdp"),
    "india_dpdp": ("india", "dpdp"),
    "india dpdp": ("india", "dpdp"),
    # NIST AI RMF
    "nist_ai_rmf": ("us", "nist_ai_rmf"),
    "nist ai rmf": ("us", "nist_ai_rmf"),
    "nist ai": ("us", "nist_ai_rmf"),
    "ai rmf": ("us", "nist_ai_rmf"),
    "ai_rmf": ("us", "nist_ai_rmf"),
    "airmf": ("us", "nist_ai_rmf"),
    # NIST CSF
    "csf": ("nist", "csf"),
    "nist_csf": ("nist", "csf"),
    "nist csf": ("nist", "csf"),
    # NIST CLOUD
    "cloud": ("nist", "cloud"),
    "nist_cloud": ("nist", "cloud"),
    "nist cloud": ("nist", "cloud"),
    # NIST ZERO TRUST
    "zero_trust": ("nist", "zero_trust"),
    "zerotrust": ("nist", "zero_trust"),
    "nist_zero_trust": ("nist", "zero_trust"),
    "nist zero trust": ("nist", "zero_trust"),
    # NIST IOT
    "iot": ("nist", "iot"),
    "nist_iot": ("nist", "iot"),
    "nist iot": ("nist", "iot"),
    # ISO 27001
    "iso27001": ("international", "iso27001"),
    "iso 27001": ("international", "iso27001"),
    "iso_27001": ("international", "iso27001"),
    # HIPAA, PCI, SOC2, OWASP, CWE
    "hipaa": ("us", "hipaa"),
    "pci_dss": ("us", "pci_dss"),
    "pcidss": ("us", "pci_dss"),
    "soc2": ("us", "soc2"),
    "owasp": ("international", "owasp"),
    "asvs": ("international", "asvs"),
    "wstg": ("owasp", "wstg_v42"),
    "cwe": ("cwe", "cwe_v4"),
}


class MasterAgentState(TypedDict):
    query: str
    intent: str
    base_jurisdiction: str
    base_framework: str
    compare_jurisdiction: str
    compare_framework: str
    file_path: str
    target_url: str
    repo_path: str
    controls: List[dict]
    mappings: List[dict]
    assessment: List[dict]
    discovered_endpoints: List[dict]
    probe_results: List[dict]
    report_path: str
    requires_approval: bool
    approved: bool
    execution_logs: List[str]
    output: str


def get_initial_state(query: str, approved: bool = False, file_path: str = "", target_url: str = "", repo_path: str = "") -> MasterAgentState:
    """Factory creating a valid, typed MasterAgentState dictionary."""
    return {
        "query": query,
        "intent": "",
        "base_jurisdiction": "",
        "base_framework": "",
        "compare_jurisdiction": "",
        "compare_framework": "",
        "file_path": file_path,
        "target_url": target_url,
        "repo_path": repo_path,
        "controls": [],
        "mappings": [],
        "assessment": [],
        "discovered_endpoints": [],
        "probe_results": [],
        "report_path": "",
        "requires_approval": False,
        "approved": approved,
        "execution_logs": [],
        "output": ""
    }


def node_supervisor_classifier(state: MasterAgentState) -> MasterAgentState:
    """Supervisor Node: Classifies intent and extracts dynamic parameters from the prompt."""
    query = state["query"].lower()
    logs = state.get("execution_logs", [])
    logs.append(f"[Supervisor] Analyzing prompt intent for query: '{state['query']}'")
    
    # 1. Intent Detection Matrix
    if any(k in query for k in ["probe", "scan", "live test", "dynamic test", "verify endpoint", "url"]):
        state["intent"] = "live_verification"
    elif any(k in query for k in ["ingest", "parse pdf", "parse code", "load document"]):
        state["intent"] = "ingestion_and_indexing"
    elif any(k in query for k in ["fine-tune", "train adapter", "lora", "synthesize data"]):
        state["intent"] = "fine_tuning"
        state["requires_approval"] = True
    elif any(k in query for k in ["compare", "map", "mapping", "vs", "versus"]):
        state["intent"] = "framework_mapping"
    elif any(k in query for k in ["assess", "audit", "compliance status", "report"]):
        state["intent"] = "compliance_assessment"
    elif any(k in query for k in ["onboard", "client policy", "client setup"]):
        state["intent"] = "client_onboarding"
    else:
        state["intent"] = "general_query"
        
    # 2. Dynamic Framework Parameter Extraction (Sorted by length descending to match multi-word aliases first)
    found_frameworks = []
    sorted_aliases = sorted(KNOWN_FRAMEWORKS.keys(), key=len, reverse=True)
    
    for alias in sorted_aliases:
        jur, fw_key = KNOWN_FRAMEWORKS[alias]
        if re.search(r'\b' + re.escape(alias) + r'\b', query):
            pair = (fw_key, jur)
            if pair not in found_frameworks:
                found_frameworks.append(pair)
            
    if found_frameworks:
        if not state.get("base_framework"):
            state["base_framework"] = found_frameworks[0][0]
            state["base_jurisdiction"] = found_frameworks[0][1]
        if len(found_frameworks) > 1 and not state.get("compare_framework"):
            state["compare_framework"] = found_frameworks[1][0]
            state["compare_jurisdiction"] = found_frameworks[1][1]

    # 3. Dynamic URL Extraction for Live Probing
    url_match = re.search(r'https?://[^\s]+', state["query"])
    if url_match and not state.get("target_url"):
        state["target_url"] = url_match.group(0)

    logs.append(
        f"[Supervisor] Classified Intent: {state['intent']} | "
        f"Base FW: {state.get('base_framework', 'N/A')} | "
        f"Compare FW: {state.get('compare_framework', 'N/A')}"
    )
    state["execution_logs"] = logs
    return state


def node_ingestion_and_indexing(state: MasterAgentState) -> MasterAgentState:
    """Agents 1, 1B & 2: Ingests documents/code & builds knowledge base vectors."""
    logs = state.get("execution_logs", [])
    file_path = state.get("file_path", "")
    repo_path = state.get("repo_path", "")
    jur = state.get("base_jurisdiction", "nist")
    fw = state.get("base_framework", "csf")
    
    logs.append(f"[Agent 1 & 2] Processing ingestion for {jur}/{fw}...")
    try:
        extracted = []
        if file_path and os.path.exists(file_path):
            extracted = agent1.ingest_single_file(file_path, jur, fw)
            logs.append(f"[Agent 1] Extracted {len(extracted)} controls from PDF/Document '{file_path}'")
        elif repo_path and os.path.exists(repo_path):
            extracted = agent1b.ingest_codebase(repo_path, jur, fw)
            logs.append(f"[Agent 1B] Extracted {len(extracted)} code security controls from repository '{repo_path}'")
            
        # Agent 2: Index controls into ChromaDB
        all_controls = agent2.load_all_controls()
        agent2.build_chroma_collection(all_controls)
        logs.append(f"[Agent 2] Indexed controls into ChromaDB vector database.")
        
        state["controls"] = extracted
        state["output"] = f"Ingestion & Indexing complete. Processed {len(extracted)} control safeguards for {jur.upper()}/{fw.upper()}."
    except Exception as exc:
        state["output"] = f"Ingestion Agent notice: {exc}"
        logs.append(f"[Agent 1/2 Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def node_mapping_agent(state: MasterAgentState) -> MasterAgentState:
    """Agent 3: Calculates semantic similarity control mappings between frameworks."""
    logs = state.get("execution_logs", [])
    base_jur = state.get("base_jurisdiction")
    base_fw = state.get("base_framework")
    comp_jur = state.get("compare_jurisdiction")
    comp_fw = state.get("compare_framework")
    
    # If frameworks are incomplete, fallback to RAG / general LLM synthesis without forcing hardcoded defaults
    if not base_fw or not comp_fw:
        logs.append("[Agent 3] Framework pair incomplete for direct matrix mapping. Delegating to RAG LLM Node.")
        return node_general_llm(state)

    logs.append(f"[Agent 3] Mapping {base_jur}/{base_fw} vs {comp_jur}/{comp_fw}...")
    try:
        maps = agent3.map_controls(base_jur, base_fw, comp_jur, comp_fw, False)
        state["mappings"] = maps
        state["output"] = (
            f"Successfully computed {len(maps)} control mappings between "
            f"{base_jur.upper()}/{base_fw.upper()} and {comp_jur.upper()}/{comp_fw.upper()}."
        )
        logs.append(f"[Agent 3] Successfully computed {len(maps)} cross-framework mappings.")
    except Exception as exc:
        state["output"] = f"Control Mapping Agent notice: {exc}"
        logs.append(f"[Agent 3 Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def node_assessment_agent(state: MasterAgentState) -> MasterAgentState:
    """Agents 4 & 5: Assesses compliance safeguards and generates final markdown reports."""
    logs = state.get("execution_logs", [])
    jur = state.get("base_jurisdiction") or "nist"
    fw = state.get("base_framework") or "csf"
    
    logs.append(f"[Agents 4 & 5] Auditing compliance and building report for {jur}/{fw}...")
    try:
        assessment = agent4.assess_compliance(jur, fw)
        report = agent5.build_report(jur, fw, assessment, with_remediation=True)
        
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/{jur}__{fw}_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
            
        state["assessment"] = assessment
        state["report_path"] = report_path
        state["output"] = f"Compliance audit complete for {jur.upper()}/{fw.upper()}. Full report generated at '{report_path}'."
        logs.append(f"[Agent 4/5] Assessment finished ({len(assessment)} items). Report -> {report_path}")
    except Exception as exc:
        state["output"] = f"Assessment & Reporting Agent notice: {exc}"
        logs.append(f"[Agent 4/5 Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def node_live_verification_agent(state: MasterAgentState) -> MasterAgentState:
    """Agents X, Y & Z: Conducts dynamic endpoint discovery, security probing, and evidence mapping."""
    logs = state.get("execution_logs", [])
    target_url = state.get("target_url") or "http://localhost:8000"
    
    logs.append(f"[Agents X/Y/Z] Initiating live security verification on target '{target_url}'...")
    if not PROBING_AGENTS_AVAILABLE:
        state["output"] = f"Live verification agents (X/Y/Z) are not initialized in this environment."
        return state
        
    try:
        # 1. Agent X: Endpoint Discovery
        agent_x_inst = agent_x.AgentXDiscovery(target_url=target_url)
        endpoints = agent_x_inst.discover_heuristic_routes()
        logs.append(f"[Agent X] Discovered {len(endpoints)} active endpoints.")
        
        # 2. Agent Y: Dynamic Security Probing
        agent_y_inst = agent_y.AgentYDynamicProbes(target_url=target_url, allow_local_dev=True)
        probe_results = agent_y_inst.run_all()
        logs.append(f"[Agent Y] Executed {len(probe_results)} security test probes.")
        
        # 3. Agent Z: Compliance Verification Mapping
        verification_report = agent_z.verify_and_map_evidence(probe_results)
        logs.append(f"[Agent Z] Mapped evidence to security controls.")
        
        state["discovered_endpoints"] = endpoints
        state["probe_results"] = probe_results
        state["output"] = (
            f"Live Verification Complete for '{target_url}'.\n"
            f"- Discovered Endpoints: {len(endpoints)}\n"
            f"- Probes Executed: {len(probe_results)}\n"
            f"- Verification Result: {verification_report.get('status', 'Completed')}"
        )
    except Exception as exc:
        state["output"] = f"Live Verification Agent notice: {exc}"
        logs.append(f"[Agent X/Y/Z Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def node_synthesis_and_tuning_agent(state: MasterAgentState) -> MasterAgentState:
    """Agents 0, 6 & 7: Synthesizes Q&A datasets and fine-tunes custom LoRA model adapters."""
    logs = state.get("execution_logs", [])
    
    # Human-in-the-Loop Gate Check
    if state.get("requires_approval") and not state.get("approved"):
        state["output"] = (
            "APPROVAL REQUIRED: Fine-tuning a new LoRA model adapter consumes system GPU/CPU resources. "
            "Please confirm execution to proceed."
        )
        logs.append("[Agent 7] Fine-tuning paused awaiting human-in-the-loop user approval.")
        state["execution_logs"] = logs
        return state
        
    file_path = state.get("file_path", "")
    jur = state.get("base_jurisdiction") or "us"
    fw = state.get("base_framework") or "custom"
    
    logs.append(f"[Agents 0/6/7] Starting dataset synthesis & LoRA fine-tuning for {jur}/{fw}...")
    try:
        res = agent0_master.run_agent0_pipeline(
            file_path=file_path if os.path.exists(file_path) else "standards/nist/csf/csf.pdf",
            jurisdiction=jur,
            framework=fw,
            epochs=1
        )
        state["output"] = f"Data Synthesis & LoRA Adapter Fine-Tuning complete for {jur.upper()}/{fw.upper()} in {res.get('total_time_seconds', 0):.1f}s."
        logs.append(f"[Agent 7] Adapter training finished successfully.")
    except Exception as exc:
        state["output"] = f"LoRA Fine-Tuning Agent notice: {exc}"
        logs.append(f"[Agent 6/7 Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def node_client_onboarding(state: MasterAgentState) -> MasterAgentState:
    """Client Onboarding Engine: Processes organization profile and generates compliance policies."""
    logs = state.get("execution_logs", [])
    logs.append("[Onboarding Engine] Running enterprise client onboarding...")
    
    if not ONBOARDING_AVAILABLE:
        state["output"] = "Client Onboarding Engine is not available."
        return state
        
    try:
        res = onboarding_engine.run_onboarding({"company_name": "Enterprise Client", "jurisdiction": state.get("base_jurisdiction", "eu")})
        state["output"] = f"Client Onboarding completed. Policy portfolio generated for {res.get('company_name', 'Client')}."
        logs.append("[Onboarding Engine] Client onboarding complete.")
    except Exception as exc:
        state["output"] = f"Onboarding Engine notice: {exc}"
        logs.append(f"[Onboarding Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def node_general_llm(state: MasterAgentState) -> MasterAgentState:
    """LangChain Local Model Pipeline: Answers general compliance and security queries."""
    logs = state.get("execution_logs", [])
    logs.append("[General LLM Node] Invoking LangChain model pipeline...")
    try:
        response = agent_config.generate(state["query"])
        state["output"] = response
        logs.append("[General LLM Node] Generation complete.")
    except Exception as exc:
        state["output"] = f"Generation error: {exc}"
        logs.append(f"[LLM Node Error] {exc}")
        
    state["execution_logs"] = logs
    return state


def route_by_intent(state: MasterAgentState) -> str:
    """Supervisor Conditional Router Edge."""
    intent = state.get("intent")
    if intent == "live_verification":
        return "live_verification"
    elif intent == "ingestion_and_indexing":
        return "ingestion_and_indexing"
    elif intent == "fine_tuning":
        return "synthesis_and_tuning"
    elif intent == "framework_mapping":
        return "mapping_agent"
    elif intent == "compliance_assessment":
        return "assessment_agent"
    elif intent == "client_onboarding":
        return "client_onboarding"
    return "general_llm"


def build_master_compliance_graph():
    """Builds and compiles the Master Multi-Agent LangGraph Application."""
    graph = StateGraph(MasterAgentState)
    
    # Register all agent nodes
    graph.add_node("supervisor", node_supervisor_classifier)
    graph.add_node("ingestion_and_indexing", node_ingestion_and_indexing)
    graph.add_node("mapping_agent", node_mapping_agent)
    graph.add_node("assessment_agent", node_assessment_agent)
    graph.add_node("live_verification", node_live_verification_agent)
    graph.add_node("synthesis_and_tuning", node_synthesis_and_tuning_agent)
    graph.add_node("client_onboarding", node_client_onboarding)
    graph.add_node("general_llm", node_general_llm)
    
    # Set supervisor entry point
    graph.set_entry_point("supervisor")
    
    # Add conditional supervisor edges
    graph.add_conditional_edges(
        "supervisor",
        route_by_intent,
        {
            "live_verification": "live_verification",
            "ingestion_and_indexing": "ingestion_and_indexing",
            "synthesis_and_tuning": "synthesis_and_tuning",
            "mapping_agent": "mapping_agent",
            "assessment_agent": "assessment_agent",
            "client_onboarding": "client_onboarding",
            "general_llm": "general_llm"
        }
    )
    
    # Wire terminal edges back to END
    graph.add_edge("ingestion_and_indexing", END)
    graph.add_edge("mapping_agent", END)
    graph.add_edge("assessment_agent", END)
    graph.add_edge("live_verification", END)
    graph.add_edge("synthesis_and_tuning", END)
    graph.add_edge("client_onboarding", END)
    graph.add_edge("general_llm", END)
    
    return graph.compile()


if __name__ == "__main__":
    app = build_master_compliance_graph()
    
    test_queries = [
        "what is the difference between nist ai rmf and dpd",
        "Compare GDPR and NIS2",
    ]
    
    for q in test_queries:
        test_state = {
            "query": q,
            "base_jurisdiction": "",
            "base_framework": "",
            "compare_jurisdiction": "",
            "compare_framework": "",
            "file_path": "",
            "target_url": "",
            "repo_path": "",
            "controls": [],
            "mappings": [],
            "assessment": [],
            "discovered_endpoints": [],
            "probe_results": [],
            "report_path": "",
            "requires_approval": False,
            "approved": False,
            "execution_logs": [],
            "output": ""
        }
        
        print(f"\n=======================================================")
        print(f"Testing Master Multi-Agent Graph: '{q}'")
        print(f"=======================================================")
        res = app.invoke(test_state)
        print("Output:", res["output"])
        print("Logs:", res["execution_logs"])
