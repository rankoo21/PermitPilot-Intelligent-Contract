# PermitPilot

PermitPilot is a GenLayer Intelligent Contract for evidence-based permit review. Validators independently inspect official rules and submitted evidence from distinct HTTPS hosts, then reach consensus on APPROVE, REMEDIATE, or REJECT. The contract stores the ruling, missing requirements, reason, source digests, and appeal state.

## Contract

`contracts/permit_pilot.py`

## Verification

```text
genvm-lint contracts/permit_pilot.py
python -m pytest tests -q
```

Deployment: GenLayer Studionet. See `artifacts/deployment.json`.
