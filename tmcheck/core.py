"""Core checker for Rawaj Pay threat models."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


class ModelError(Exception):
    """Raised when a model file cannot be loaded."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str
    category: str


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str


STRIDE = {"S", "T", "R", "I", "D", "E"}
STRIDE_ORDER = {"S": 0, "T": 1, "R": 2, "I": 3, "D": 4, "E": 5}
ELEMENT_KINDS = {"external_entity", "process", "data_store"}
FLOW_KINDS = {"data_flow"}
STATUSES = {"open", "mitigated", "accepted"}
ENCRYPTED_PROTOCOLS = {"https", "tls", "mtls", "sftp", "ssh"}

SECTIONS = ("zones", "elements", "flows", "threats")


def _is_score_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 5


def _is_nonblank(value) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _natural_key(text: str):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text)]


def _applicable_for_element(element: dict) -> set[str]:
    kind = element.get("kind")
    is_log = element.get("is_log") is True
    return applicable(kind, is_log=is_log)


def load_model(path) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, TypeError) as exc:
        raise ModelError(f"cannot read {path!r}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ModelError(f"invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ModelError("top level must be a mapping")

    model = {}
    for section in SECTIONS:
        value = data.get(section, [])
        if value is None:
            value = []
        if not isinstance(value, list):
            raise ModelError(f"section {section!r} must be a list")
        model[section] = value
    return model


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set(STRIDE)
    if kind == "data_store":
        cats = {"T", "I", "D"}
        if is_log:
            cats.add("R")
        return cats
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"unknown kind: {kind!r}")


def validate(model: dict) -> list[Issue]:
    issues: set[Issue] = set()

    zones = model["zones"]
    elements = model["elements"]
    flows = model["flows"]
    threats = model["threats"]

    zone_ids = {z.get("id") for z in zones}
    element_ids = {e.get("id") for e in elements}
    flow_ids = {f.get("id") for f in flows}

    element_by_id = {e.get("id"): e for e in elements}

    seen: set = set()
    for item in zones + elements + flows + threats:
        ident = item.get("id")
        if ident in seen:
            issues.add(Issue(ref=ident, code="DUPLICATE_ID"))
        else:
            seen.add(ident)

    for element in elements:
        eid = element.get("id")
        if element.get("kind") not in ELEMENT_KINDS:
            issues.add(Issue(ref=eid, code="BAD_KIND"))
        if element.get("zone") not in zone_ids:
            issues.add(Issue(ref=eid, code="UNKNOWN_ZONE"))

    for flow in flows:
        fid = flow.get("id")
        source = flow.get("source")
        target = flow.get("target")

        if source not in element_ids or target not in element_ids:
            issues.add(Issue(ref=fid, code="UNKNOWN_REF"))
            continue

        if source == target:
            issues.add(Issue(ref=fid, code="INVALID_FLOW"))
            continue

        src_kind = element_by_id[source].get("kind")
        tgt_kind = element_by_id[target].get("kind")
        if src_kind != "process" and tgt_kind != "process":
            issues.add(Issue(ref=fid, code="INVALID_FLOW"))

    for threat in threats:
        tid = threat.get("id")
        target = threat.get("target")
        category = threat.get("category")

        target_is_element = target in element_ids
        target_is_flow = target in flow_ids

        if not target_is_element and not target_is_flow:
            issues.add(Issue(ref=tid, code="UNKNOWN_REF"))
        else:
            if not isinstance(category, str) or category not in STRIDE:
                issues.add(Issue(ref=tid, code="BAD_CATEGORY"))
            else:
                if target_is_element:
                    allowed = _applicable_for_element(element_by_id[target])
                else:
                    allowed = applicable("data_flow")
                if category not in allowed:
                    issues.add(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))

        if not (
            _is_score_int(threat.get("likelihood"))
            and _is_score_int(threat.get("impact"))
        ):
            issues.add(Issue(ref=tid, code="BAD_SCORE"))

        status = threat.get("status")
        if status not in STATUSES:
            issues.add(Issue(ref=tid, code="BAD_STATUS"))
        elif status == "mitigated" and not _is_nonblank(threat.get("mitigation")):
            issues.add(Issue(ref=tid, code="MISSING_MITIGATION"))
        elif status == "accepted" and not _is_nonblank(threat.get("justification")):
            issues.add(Issue(ref=tid, code="MISSING_JUSTIFICATION"))

    return sorted(issues)


def crossing_flows(model: dict) -> list[str]:
    element_by_id = {e.get("id"): e for e in model["elements"]}
    result: list[str] = []

    for flow in model["flows"]:
        source = flow.get("source")
        target = flow.get("target")
        if source not in element_by_id or target not in element_by_id:
            continue
        zone_src = element_by_id[source].get("zone")
        zone_tgt = element_by_id[target].get("zone")
        if zone_src != zone_tgt:
            result.append(flow.get("id"))
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    element_by_id = {e.get("id"): e for e in model["elements"]}
    flow_by_id = {f.get("id"): f for f in model["flows"]}

    crossing = crossing_flows(model)

    scope: set[str] = set(crossing)
    for fid in crossing:
        flow = flow_by_id[fid]
        scope.add(flow.get("source"))
        scope.add(flow.get("target"))

    covered = {(t.get("target"), t.get("category")) for t in model["threats"]}

    gaps: list[Gap] = []
    for ref in scope:
        if ref in element_by_id:
            categories = _applicable_for_element(element_by_id[ref])
        else:
            categories = applicable("data_flow")
        for category in categories:
            if (ref, category) not in covered:
                gaps.append(Gap(ref=ref, category=category))

    gaps.sort(key=lambda g: (g.ref, STRIDE_ORDER[g.category]))
    return gaps


def policy_findings(model: dict) -> list[Issue]:
    issues: list[Issue] = []

    element_by_id = {e.get("id"): e for e in model["elements"]}
    zone_by_id = {z.get("id"): z for z in model["zones"]}
    crossing = set(crossing_flows(model))

    for flow in model["flows"]:
        fid = flow.get("id")
        if fid not in crossing:
            continue
        protocol = flow.get("protocol")
        if not (isinstance(protocol, str) and protocol.lower() in ENCRYPTED_PROTOCOLS):
            issues.append(Issue(ref=fid, code="UNENCRYPTED_CROSSING"))

    for flow in model["flows"]:
        fid = flow.get("id")
        if fid not in crossing:
            continue

        source = element_by_id.get(flow.get("source"))
        target = element_by_id.get(flow.get("target"))
        if source is None or target is None:
            continue

        zone_src = zone_by_id.get(source.get("zone"))
        zone_tgt = zone_by_id.get(target.get("zone"))
        if zone_src is None or zone_tgt is None:
            continue

        src_trust = zone_src.get("trust", 0)
        tgt_trust = zone_tgt.get("trust", 0)
        if tgt_trust > src_trust and flow.get("authenticated") is not True:
            issues.append(Issue(ref=fid, code="UNAUTHENTICATED_INBOUND"))

    i_targets = {
        t.get("target") for t in model["threats"] if t.get("category") == "I"
    }
    for element in model["elements"]:
        if element.get("kind") == "data_store" and element.get("holds_pii") is True:
            if element.get("id") not in i_targets:
                issues.append(Issue(ref=element.get("id"), code="PII_STORE_WITHOUT_I_THREAT"))

    return sorted(issues)


def rank(model: dict) -> list[RankedThreat]:
    impact_by_id: dict[str, int] = {}
    ranked: list[RankedThreat] = []

    for threat in model["threats"]:
        tid = threat.get("id")
        if threat.get("status") != "open":
            continue
        likelihood = threat.get("likelihood")
        impact = threat.get("impact")
        if not (_is_score_int(likelihood) and _is_score_int(impact)):
            continue

        impact_by_id[tid] = impact
        score = likelihood * impact
        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"
        ranked.append(RankedThreat(id=tid, score=score, level=level))

    ranked.sort(key=lambda r: (-r.score, -impact_by_id[r.id], _natural_key(r.id)))
    return ranked
