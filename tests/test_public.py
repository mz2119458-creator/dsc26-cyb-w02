from pathlib import Path

import pytest

from tmcheck.core import (
    Gap, ModelError, applicable, coverage_gaps, crossing_flows, load_model,
    policy_findings, rank, validate,
)


def tiny_model():
    return {
        "zones": [{"id": "internet", "trust": 0}, {"id": "core", "trust": 2}],
        "elements": [
            {"id": "user", "kind": "external_entity", "zone": "internet"},
            {"id": "api", "kind": "process", "zone": "core"},
            {"id": "db", "kind": "data_store", "zone": "core", "holds_pii": True},
        ],
        "flows": [
            {"id": "f1", "source": "user", "target": "api", "protocol": "https", "authenticated": True},
            {"id": "f2", "source": "api", "target": "db", "protocol": "tls", "authenticated": True},
        ],
        "threats": [],
    }


def test_stride_per_element():
    assert applicable("external_entity") == {"S", "R"}
    assert applicable("process") == set("STRIDE")
    assert applicable("data_flow") == {"T", "I", "D"}
    assert applicable("data_store", is_log=True) == {"T", "R", "I", "D"}


def test_flow_between_two_stores_is_invalid():
    m = tiny_model()
    m["elements"].append({"id": "backup", "kind": "data_store", "zone": "core"})
    m["flows"].append({"id": "f3", "source": "db", "target": "backup", "protocol": "tls"})
    assert ("f3", "INVALID_FLOW") in {(i.ref, i.code) for i in validate(m)}


def test_only_the_crossing_flow_is_in_scope():
    m = tiny_model()
    assert crossing_flows(m) == ["f1"]
    gaps = coverage_gaps(m)
    assert Gap("f1", "T") in gaps and Gap("user", "S") in gaps
    assert all(g.ref != "f2" and g.ref != "db" for g in gaps)


def test_rank_orders_by_score_then_impact():
    m = tiny_model()
    m["threats"] = [
        {"id": "T1", "target": "api", "category": "D", "title": "x", "likelihood": 4, "impact": 2, "status": "open"},
        {"id": "T2", "target": "api", "category": "S", "title": "y", "likelihood": 2, "impact": 4, "status": "open"},
        {"id": "T3", "target": "f1", "category": "T", "title": "z", "likelihood": 5, "impact": 5, "status": "mitigated",
         "mitigation": "TLS"},
    ]
    assert [r.id for r in rank(m)] == ["T2", "T1"]
    assert rank(m)[0].level == "medium"


def test_unsafe_yaml_tag_is_refused(tmp_path: Path):
    p = tmp_path / "evil.yaml"
    p.write_text("zones: !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(ModelError):
        load_model(p)
