from pathlib import Path

SOURCE = (Path(__file__).parents[1] / "contracts" / "permit_pilot.py").read_text()

def test_permit_pilot_consensus_and_lifecycle():
    assert "gl.nondet.web.get" in SOURCE
    assert "gl.nondet.exec_prompt" in SOURCE
    assert "gl.vm.run_nondet_unsafe" in SOURCE
    assert '"APPROVE"' in SOURCE and '"REMEDIATE"' in SOURCE and '"REJECT"' in SOURCE
    assert "submit_for_review" in SOURCE
    assert "appeal" in SOURCE

def test_permit_pilot_guards():
    assert "application ID already exists" in SOURCE
    assert "distinct hosts" in SOURCE
    assert "application is not under review" in SOURCE
