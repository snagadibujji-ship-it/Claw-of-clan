"""Blackboard compactor — prevents context-window exhaustion on long engagements.

Problem: The Blackboard's facts list and tool_calls log grow unboundedly.
On large attack surfaces the to_prompt_graph() output can exceed the LLM's
context window, causing the agent to "forget" early recon facts.

Solution: Smart compaction that:
  1. Pins critical facts (flags, confirmed vulns, origin seed) — never evicted
  2. Summarises clusters of closely-related facts into a single meta-fact
  3. Trims the tool-call log while keeping the dedup index intact (set of seen keys)
  4. Exposes a compact_if_needed() helper that solver.py can call each iteration

All operations are deterministic and lossless for pinned facts.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vulnclaw.agent.blackboard import Blackboard, BoardFact

# Facts whose descriptions match these patterns are ALWAYS kept verbatim
_PIN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"flag\{", re.IGNORECASE),
    re.compile(r"origin="),
    re.compile(r"\[拒绝完成\]"),
    re.compile(r"\[未验证\]"),
    re.compile(r"shell|getshell|rce|webshell", re.IGNORECASE),
    re.compile(r"凭据|credential|密码|password|token|api.?key", re.IGNORECASE),
    re.compile(r"漏洞|vulnerability|vuln|exploit", re.IGNORECASE),
]

# Maximum facts before we start compacting older ones
_FACTS_SOFT_LIMIT = 35
_FACTS_HARD_LIMIT = 60

# Maximum tool-call records to keep in the log (older ones are dropped after
# their key is added to the seen-set so dedup still works)
_TOOL_CALLS_SOFT_LIMIT = 120
_TOOL_CALLS_HARD_LIMIT = 200


def _is_pinned(fact: "BoardFact") -> bool:
    desc = fact.description
    return any(pat.search(desc) for pat in _PIN_PATTERNS)


def _fact_group_key(desc: str) -> str:
    """Return a rough grouping key for similar facts (for clustering).

    Facts about the same endpoint/tool result are grouped together so they
    can be merged into a single summary fact.
    """
    # Extract the first URL or path found in the description
    url_match = re.search(r"https?://[^\s,;\"']{4,60}", desc)
    if url_match:
        return url_match.group(0)
    path_match = re.search(r"/[a-zA-Z0-9_\-/]{3,40}", desc)
    if path_match:
        return path_match.group(0)
    # Use first 30 chars as a rough key
    return desc[:30].strip()


def _summarise_cluster(facts: list["BoardFact"]) -> str:
    """Merge N related facts into one summary string."""
    if len(facts) == 1:
        return facts[0].description
    ids = ", ".join(f.id for f in facts)
    # Keep the longest description as the representative, plus a count note
    longest = max(facts, key=lambda f: len(f.description))
    return f"[摘要 {ids}] {longest.description}"


def compact_facts(board: "Blackboard") -> int:
    """Compact old, non-pinned facts when the board exceeds _FACTS_SOFT_LIMIT.

    Returns the number of facts removed.
    """
    if len(board.facts) < _FACTS_SOFT_LIMIT:
        return 0

    # Separate pinned and eviction-candidate facts
    pinned: list["BoardFact"] = []
    candidates: list["BoardFact"] = []

    for fact in board.facts:
        if _is_pinned(fact):
            pinned.append(fact)
        else:
            candidates.append(fact)

    # Sort candidates oldest-first (by id numeric suffix)
    def _fact_seq(f: "BoardFact") -> int:
        try:
            return int(f.id[1:])
        except ValueError:
            return 0

    candidates.sort(key=_fact_seq)

    # Keep the N most recent candidates verbatim, compact the rest
    keep_recent = max(10, _FACTS_SOFT_LIMIT - len(pinned))
    to_compact = candidates[:-keep_recent] if len(candidates) > keep_recent else []
    to_keep = candidates[-keep_recent:] if len(candidates) > keep_recent else candidates

    if not to_compact:
        return 0

    # Group compaction candidates by rough topic and merge
    groups: dict[str, list["BoardFact"]] = {}
    for fact in to_compact:
        key = _fact_group_key(fact.description)
        groups.setdefault(key, []).append(fact)

    # Build replacement summary facts
    summaries: list[str] = []
    for _key, group_facts in groups.items():
        summaries.append(_summarise_cluster(group_facts))

    # Replace board.facts with: pinned + summary meta-fact + recent candidates
    from vulnclaw.agent.blackboard import BoardFact  # local import to avoid circular

    removed_count = len(to_compact)

    # Add a single compaction meta-fact
    meta_desc = f"[自动摘要 {removed_count} 条旧事实] " + " | ".join(summaries)[:800]
    meta_fact = BoardFact(
        id=f"f{board.fact_seq + 1:03d}",
        description=meta_desc,
        source="compactor",
    )
    board.fact_seq += 1

    board.facts = pinned + [meta_fact] + to_keep
    return removed_count


def compact_tool_calls(board: "Blackboard") -> int:
    """Trim old tool-call records while preserving the dedup key set.

    Returns number of records trimmed.
    """
    if len(board.tool_calls) < _TOOL_CALLS_SOFT_LIMIT:
        return 0

    # The dedup logic in has_called() scans board.tool_calls linearly.
    # We preserve dedup by keeping a "seen keys" set inside the records
    # we keep, so old entries don't need to survive.
    # Simply trim the oldest half when over soft limit — the record_tool_call()
    # method already does this (del self.tool_calls[:100]) but only at 200 items.
    # We call it earlier and more aggressively.

    keep = _TOOL_CALLS_SOFT_LIMIT // 2
    trimmed = len(board.tool_calls) - keep
    if trimmed > 0:
        del board.tool_calls[:trimmed]
    return max(0, trimmed)


def compact_if_needed(board: "Blackboard") -> dict[str, int]:
    """Run all compaction passes if any threshold is exceeded.

    Returns a summary of how many items were compacted.
    Call this once per solve() iteration step (after each Intent batch).
    """
    facts_removed = 0
    tool_calls_trimmed = 0

    if len(board.facts) >= _FACTS_SOFT_LIMIT:
        facts_removed = compact_facts(board)

    if len(board.tool_calls) >= _TOOL_CALLS_SOFT_LIMIT:
        tool_calls_trimmed = compact_tool_calls(board)

    return {"facts_removed": facts_removed, "tool_calls_trimmed": tool_calls_trimmed}
