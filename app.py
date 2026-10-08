"""SchemaBreaker Standalone Web Application.

Run with:
    python app.py
    # or
    uvicorn app:app --reload --port 8501
"""

import asyncio
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from schemabreaker.core.models import (
    AttackVector,
    AuditSummary,
    FailureCategory,
    FuzzConfig,
    Recommendation,
    TestCase,
    TestResult,
)
from schemabreaker.core.loader import (
    load_schema_from_code,
    _create_model_from_json_schema,
    SchemaInspector,
)
from schemabreaker.core.fuzzer import AdversarialFuzzer
from schemabreaker.core.runner import ValidationRunner
from schemabreaker.core.analyzer import SchemaAnalyzer
from schemabreaker.ui.export import export_html, export_json


# Initialize FastAPI
app = FastAPI(
    title="SchemaBreaker Web Application",
    description="Automated stress-testing & adversarial fuzzing for LLM Structured Outputs",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# Request Payload for /api/run-audit
class RunAuditRequest(BaseModel):
    schema_definition: str = Field(..., description="Raw Pydantic model code or JSON Schema string")
    system_prompt: Optional[str] = Field(default=None, description="Target LLM system instruction")
    iterations: int = Field(default=20, ge=3, le=40, description="Number of concurrent adversarial test variations")
    target_model: str = Field(default="gemini-2.5-flash", description="Target Gemini model")
    generator_model: str = Field(default="gemini-2.5-flash", description="Red team generator model")
    concurrency: int = Field(default=5, ge=1, le=10, description="Async concurrency limit")
    temperature: float = Field(default=0.2, ge=0.0, le=1.0, description="Sampling temperature")
    mock_mode: Optional[bool] = Field(default=None, description="True for simulated response, False for live API")
    api_key: Optional[str] = Field(default=None, description="Client-provided Gemini API Key (BYOK)")
    fault_classes: Optional[List[str]] = Field(default=None, description="Active fault classes to probe")


def _compile_schema(schema_def: str, system_prompt: Optional[str]) -> SchemaInspector:
    """Dynamically compiles user-provided Pydantic code or JSON Schema into a SchemaInspector."""
    prompt = system_prompt or "Extract structured data conforming strictly to the schema."
    schema_clean = schema_def.strip()

    if schema_clean.startswith("{") and schema_clean.endswith("}"):
        try:
            parsed = json.loads(schema_clean)
            model_cls = _create_model_from_json_schema(parsed, "DynamicJsonModel")
            return SchemaInspector(model_cls, system_prompt=prompt, source_code=schema_clean)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON Schema: {e}")
    else:
        try:
            return load_schema_from_code(
                code_str=schema_clean,
                system_prompt=prompt,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error compiling Pydantic model code: {e}")


def _resolve_api_key(req_key: Optional[str], header_key: Optional[str]) -> tuple[Optional[str], bool]:
    """Resolves API key and determines if running in Live or Mock Demo Mode."""
    key = req_key or header_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if key and key.strip():
        return key.strip(), False
    return None, True


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the single-page application dashboard."""
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    has_env_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    return {
        "status": "healthy",
        "service": "SchemaBreaker Web Application",
        "version": "0.1.0",
        "byok_enabled": True,
        "server_has_env_key": has_env_key,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/run-audit")
async def run_audit_endpoint(
    req: RunAuditRequest,
    x_gemini_api_key: Optional[str] = Header(default=None)
):
    """Executes the full stress-test audit pipeline and returns the complete summary."""
    inspector = _compile_schema(req.schema_definition, req.system_prompt)

    api_key, is_mock_default = _resolve_api_key(req.api_key, x_gemini_api_key)
    is_mock = req.mock_mode if req.mock_mode is not None else is_mock_default

    config = FuzzConfig(
        target_model=req.target_model,
        generator_model=req.generator_model,
        num_tests=req.iterations,
        concurrency=req.concurrency,
        temperature=req.temperature,
        mock_mode=is_mock,
        api_key=api_key if not is_mock else None,
    )

    started_at = datetime.now(timezone.utc)

    # 1. Generate adversarial test cases across the 4 fault classes
    fuzzer = AdversarialFuzzer(inspector, config)
    test_cases = await fuzzer.generate_test_suite(req.iterations)

    # 2. Run concurrent validation
    runner = ValidationRunner(inspector, config)
    results = await runner.run_suite(test_cases)

    completed_at = datetime.now(timezone.utc)

    # 3. Analyze results & synthesize remediation patches
    analyzer = SchemaAnalyzer(
        inspector=inspector,
        results=results,
        target_model_name=req.target_model,
        started_at=started_at,
        completed_at=completed_at,
    )
    summary = analyzer.generate_summary()

    return summary.model_dump(mode="json")


@app.post("/api/run-audit/stream")
async def run_audit_stream_endpoint(
    req: RunAuditRequest,
    x_gemini_api_key: Optional[str] = Header(default=None)
):
    """Server-Sent Events (SSE) streaming endpoint for live real-time test execution."""
    inspector = _compile_schema(req.schema_definition, req.system_prompt)

    api_key, is_mock_default = _resolve_api_key(req.api_key, x_gemini_api_key)
    is_mock = req.mock_mode if req.mock_mode is not None else is_mock_default

    config = FuzzConfig(
        target_model=req.target_model,
        generator_model=req.generator_model,
        num_tests=req.iterations,
        concurrency=req.concurrency,
        temperature=req.temperature,
        mock_mode=is_mock,
        api_key=api_key if not is_mock else None,
    )

    async def event_stream():
        try:
            mode_label = "Live Gemini 2.5" if not is_mock else "Demo Simulation"
            yield f"data: {json.dumps({'event': 'phase', 'message': f'Engine initialized ({mode_label}). Synthesizing adversarial vectors...'})}\n\n"
            
            fuzzer = AdversarialFuzzer(inspector, config)
            test_cases = await fuzzer.generate_test_suite(req.iterations)

            yield f"data: {json.dumps({'event': 'suite_ready', 'total': len(test_cases), 'mode': mode_label})}\n\n"

            results: List[TestResult] = []
            queue = asyncio.Queue()

            def on_done(res: TestResult):
                queue.put_nowait(res)

            started_at = datetime.now(timezone.utc)
            runner = ValidationRunner(inspector, config, on_test_complete=on_done)
            runner_task = asyncio.create_task(runner.run_suite(test_cases))

            completed_count = 0
            while completed_count < len(test_cases):
                res = await queue.get()
                results.append(res)
                completed_count += 1
                yield f"data: {json.dumps({'event': 'test_result', 'completed': completed_count, 'total': len(test_cases), 'result': res.model_dump(mode='json')})}\n\n"

            await runner_task
            completed_at = datetime.now(timezone.utc)

            yield f"data: {json.dumps({'event': 'phase', 'message': 'Calculating contract integrity score and synthesizing patches...'})}\n\n"

            analyzer = SchemaAnalyzer(
                inspector=inspector,
                results=results,
                target_model_name=req.target_model,
                started_at=started_at,
                completed_at=completed_at,
            )
            summary = analyzer.generate_summary()

            yield f"data: {json.dumps({'event': 'completed', 'summary': summary.model_dump(mode='json')})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'event': 'error', 'message': str(e), 'trace': traceback.format_exc()})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/export/html")
async def export_html_file(summary: Dict[str, Any]):
    """Exports standalone interactive HTML report."""
    try:
        audit_summary = AuditSummary.model_validate(summary)
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            export_html(audit_summary, tmp.name)
            content = Path(tmp.name).read_text(encoding="utf-8")
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=schemabreaker_{audit_summary.schema_name}.html"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"HTML Export failed: {e}")


@app.post("/api/export/json")
async def export_json_file(summary: Dict[str, Any]):
    """Exports full audit JSON telemetry."""
    try:
        audit_summary = AuditSummary.model_validate(summary)
        json_str = audit_summary.model_dump_json(indent=2)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=schemabreaker_{audit_summary.schema_name}.json"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"JSON Export failed: {e}")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8501))
    print(f"\n==================================================================")
    print(f"⚡ [latentcat // schemabreaker] Web Dashboard running!")
    print(f"👉 Open in your browser: http://{host}:{port}")
    print(f"==================================================================\n")
    uvicorn.run("app:app", host=host, port=port, reload=False)
