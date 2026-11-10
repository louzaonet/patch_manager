"""
Agent graph: the LangGraph state machine.

    START
      │
      ▼
    load_inventory ──► classify_intent
                           │
      ┌────────────────────┼──────────────────────┬──────────────────┐
      │ analyze_risk       │ apply_patches        │ check_updates     │ status        ask_question
      │ generate_report    │                      │                   │                    │
      ▼                    ▼                      ▼                   ▼                    ▼
    enrich_cves         enrich_cves           score_risks       fetch_task_status   handle_question
      ▼                    ▼                      │                   │                    │
    score_risks         score_risks               │                   │                    │
      │                    ▼                      │                   │                    │
      │               build_patch_plan            │                   │                    │
      │               (pending approval)          │                   │                    │
      └──────────► generate_briefing ◄────────────┴───────────────────┘                    │
                           │                                                               │
                           ▼                                                               ▼
                          END ◄────────────────────────────────────────────────────────────┘

Execution is deliberately NOT part of the graph: plans are approved through
/api/plans/{id}/approve (or Slack), see app/services/plans.py.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from app.agents.nodes import (
    build_patch_plan,
    classify_intent,
    enrich_cves,
    fetch_task_status,
    generate_briefing,
    handle_question,
    load_inventory,
    score_risks,
)
from app.agents.state import ActionType, AgentState


def _route_after_classify(state: AgentState) -> str:
    if state.action in (ActionType.ANALYZE_RISK, ActionType.GENERATE_REPORT, ActionType.APPLY_PATCHES):
        return "enrich_cves"
    if state.action == ActionType.CHECK_UPDATES:
        return "score_risks"
    if state.action == ActionType.STATUS:
        return "fetch_task_status"
    return "handle_question"


def _route_after_scoring(state: AgentState) -> str:
    return "build_patch_plan" if state.action == ActionType.APPLY_PATCHES else "generate_briefing"


def build_agent_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("load_inventory", load_inventory)
    graph.add_node("classify_intent", classify_intent)
    graph.add_node("enrich_cves", enrich_cves)
    graph.add_node("score_risks", score_risks)
    graph.add_node("build_patch_plan", build_patch_plan)
    graph.add_node("fetch_task_status", fetch_task_status)
    graph.add_node("generate_briefing", generate_briefing)
    graph.add_node("handle_question", handle_question)

    graph.add_edge(START, "load_inventory")
    graph.add_edge("load_inventory", "classify_intent")
    graph.add_conditional_edges(
        "classify_intent",
        _route_after_classify,
        ["enrich_cves", "score_risks", "fetch_task_status", "handle_question"],
    )
    graph.add_edge("enrich_cves", "score_risks")
    graph.add_conditional_edges(
        "score_risks", _route_after_scoring, ["build_patch_plan", "generate_briefing"]
    )
    graph.add_edge("build_patch_plan", "generate_briefing")
    graph.add_edge("fetch_task_status", "generate_briefing")
    graph.add_edge("generate_briefing", END)
    graph.add_edge("handle_question", END)
    return graph


agent = build_agent_graph().compile()


async def run_agent(state: AgentState) -> AgentState:
    """Run the graph and return the final state as an AgentState."""
    result = await agent.ainvoke(state)
    if isinstance(result, AgentState):
        return result
    return AgentState(**result)
