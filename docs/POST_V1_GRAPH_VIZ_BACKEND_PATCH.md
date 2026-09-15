# Backend patch: add the graph endpoint to your existing `backend/main.py`

I did NOT regenerate your full `backend/main.py` for this feature — that
file has grown through many phases (auth, rate limiting, async scans,
MITRE, simulation) and reconstructing it perfectly from memory risked
silently dropping something. Instead, add this one new endpoint to your
existing file by hand — it's a small, self-contained addition.

## 1. Add this endpoint anywhere among your other `GET` endpoints in `backend/main.py`

```python
@app.get("/api/v1/graph")
def get_graph(scan_id: str | None = None, user: CurrentUser = Depends(get_current_user)) -> dict:
    """Post-v1.0 — full graph payload (all nodes/edges, attack-path
    severity annotated) for the interactive attack graph frontend page."""
    from backend.graph_export import build_graph_payload

    record = service.store.get(scan_id) if scan_id else service.store.latest()
    if not record:
        raise HTTPException(status_code=404, detail="No scan available")
    return build_graph_payload(record)
```

This matches the exact same pattern your existing `list_assets`,
`list_attack_paths`, and `get_statistics` endpoints already use:
optional `scan_id` query param, `Depends(get_current_user)` (any
authenticated role — this is a read endpoint), 404 if no scan exists.

## 2. Copy the new file

`backend/graph_export.py` (included in this delivery) is a brand new
file — just drop it into your `backend/` folder. It doesn't touch or
import anything you don't already have (`backend/scan_service.py`,
which you already have from Phase 8).

## 3. No schema changes needed

The endpoint returns a plain `dict`, not a Pydantic model — the payload
shape is simple enough (nodes/edges/stats, all JSON-primitive fields)
that a full `GraphPayloadOut`/`GraphNodeOut`/`GraphEdgeOut` schema class
would be pure boilerplate for zero added safety. If you'd prefer typed
response validation for consistency with your other endpoints, the
dataclasses in `backend/graph_export.py` (`GraphNodeOut`, `GraphEdgeOut`)
already mirror the exact shape — converting them to Pydantic `BaseModel`
subclasses is a mechanical change if you want it later.

## 4. Verify

```bash
python -m pytest tests/test_graph_export.py -v
```

8 tests, fully offline (no AWS/Postgres/Redis needed) — this only
exercises graph-serialization logic against hand-built scenario data.

Then with your API running:
```bash
curl -H "Authorization: Bearer <your-token>" http://localhost:8000/api/v1/graph
```
