"""FastAPI Web Application and API Router for SchemaBreaker."""

import asyncio
import json
import os
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from schemabreaker.core.models import (
    AttackVector,
    AuditSummary,
    FuzzConfig,
    TestCase,
    TestResult,
)
from schemabreaker.core.loader import (
    load_schema_from_code,
    load_schema_from_path,
    _create_model_from_json_schema,
    SchemaInspector,
)
from schemabreaker.core.fuzzer import AdversarialFuzzer
from schemabreaker.core.runner import ValidationRunner
from schemabreaker.core.analyzer import SchemaAnalyzer
from schemabreaker.ui.export import export_html, export_json
from schemabreaker.demo import DEMO_REGISTRY, get_demo_schema


# Setup FastAPI App
app = FastAPI(
    title="SchemaBreaker Web API",
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
STATIC_DIR = BASE_DIR / "static"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class AuditRequest(BaseModel):
    """Payload for initiating a schema stress test."""
    schema_code: str = Field(..., description="Pydantic Python code or JSON Schema string")
    schema_type: str = Field(default="python", description="'python' or 'json'")
    model_name: Optional[str] = Field(default=None, description="Class name of Pydantic model")
    system_prompt: Optional[str] = Field(default=None, description="Target system prompt")
    target_model: str = Field(default="gemini-2.5-flash", description="Target Gemini model")
    generator_model: str = Field(default="gemini-2.5-flash", description="Red team generator model")
    num_tests: int = Field(default=20, ge=3, le=60, description="Number of fuzz scenarios")
    concurrency: int = Field(default=5, ge=1, le=10, description="Async concurrency limit")
    temperature: float = Field(default=0.2, ge=0.0, le=1.0, description="Sampling temperature")
    mock_mode: bool = Field(default=True, description="True for simulated response, False for live API")
    api_key: Optional[str] = Field(default=None, description="Gemini API Key")
    attack_vectors: Optional[List[str]] = Field(default=None, description="List of attack vector names")


def _build_inspector(req: AuditRequest) -> SchemaInspector:
    """Instantiates SchemaInspector from request code or JSON Schema."""
    prompt = req.system_prompt or "Extract structured data conforming strictly to the schema."
    
    if req.schema_type == "json":
        try:
            parsed_json = json.loads(req.schema_code)
            model_cls = _create_model_from_json_schema(parsed_json, req.model_name or "JsonModel")
            return SchemaInspector(model_cls, system_prompt=prompt, source_code=req.schema_code)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON Schema: {e}")
    else:
        try:
            return load_schema_from_code(
                code_str=req.schema_code,
                model_name=req.model_name,
                system_prompt=prompt,
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error compiling Pydantic model: {e}")


@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Serves the main single-page application dashboard."""
    return templates.TemplateResponse(request, "index.html")


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SchemaBreaker Web",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/demos")
async def list_demos():
    """Returns all pre-packaged demonstration schemas and system prompts."""
    demos = []
    for key, (cls, prompt, desc) in DEMO_REGISTRY.items():
        # Get source code from demo file
        import inspect
        source = inspect.getsource(cls)
        demos.append({
            "key": key,
            "name": cls.__name__,
            "description": desc,
            "system_prompt": prompt,
            "schema_code": source,
        })
    return {"demos": demos}


@app.post("/api/audit")
async def run_audit_sync(req: AuditRequest):
    """Executes the full stress-test audit pipeline and returns the complete summary."""
    inspector = _build_inspector(req)

    # API key fallback to environment
    api_key = req.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    effective_mock = req.mock_mode or not bool(api_key)

    vectors = [AttackVector(v) for v in req.attack_vectors] if req.attack_vectors else None

    config = FuzzConfig(
        target_model=req.target_model,
        generator_model=req.generator_model,
        num_tests=req.num_tests,
        concurrency=req.concurrency,
        temperature=req.temperature,
        mock_mode=effective_mock,
        api_key=api_key if not effective_mock else None,
        attack_vectors=vectors,
    )

    started_at = datetime.now(timezone.utc)
    
    # 1. Generate test cases
    fuzzer = AdversarialFuzzer(inspector, config)
    test_cases = await fuzzer.generate_test_suite(req.num_tests)

    # 2. Run concurrent validation
    runner = ValidationRunner(inspector, config)
    results = await runner.run_suite(test_cases)

    completed_at = datetime.now(timezone.utc)

    # 3. Analyze results
    analyzer = SchemaAnalyzer(
        inspector=inspector,
        results=results,
        target_model_name=req.target_model,
        started_at=started_at,
        completed_at=completed_at,
    )
    summary = analyzer.generate_summary()

    return summary.model_dump(mode="json")


@app.post("/api/audit/stream")
async def run_audit_stream(req: AuditRequest):
    """Server-Sent Events (SSE) streaming endpoint for real-time progress and live test updates."""
    inspector = _build_inspector(req)

    api_key = req.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    effective_mock = req.mock_mode or not bool(api_key)
    vectors = [AttackVector(v) for v in req.attack_vectors] if req.attack_vectors else None

    config = FuzzConfig(
        target_model=req.target_model,
        generator_model=req.generator_model,
        num_tests=req.num_tests,
        concurrency=req.concurrency,
        temperature=req.temperature,
        mock_mode=effective_mock,
        api_key=api_key if not effective_mock else None,
        attack_vectors=vectors,
    )

    async def event_generator():
        try:
            yield f"data: {json.dumps({'event': 'phase', 'message': 'Introspecting schema and generating adversarial vectors...'})}\n\n"
            
            fuzzer = AdversarialFuzzer(inspector, config)
            test_cases = await fuzzer.generate_test_suite(req.num_tests)

            yield f"data: {json.dumps({'event': 'suite_ready', 'total': len(test_cases), 'cases': [tc.model_dump(mode='json') for tc in test_cases]})}\n\n"

            results: List[TestResult] = []
            queue = asyncio.Queue()

            def on_test_done(result: TestResult):
                queue.put_nowait(result)

            started_at = datetime.now(timezone.utc)
            runner = ValidationRunner(inspector, config, on_test_complete=on_test_done)
            
            runner_task = asyncio.create_task(runner.run_suite(test_cases))

            completed_count = 0
            while completed_count < len(test_cases):
                result = await queue.get()
                results.append(result)
                completed_count += 1
                
                yield f"data: {json.dumps({'event': 'test_result', 'completed': completed_count, 'total': len(test_cases), 'result': result.model_dump(mode='json')})}\n\n"

            await runner_task
            completed_at = datetime.now(timezone.utc)

            yield f"data: {json.dumps({'event': 'phase', 'message': 'Synthesizing health score & recommendations...'})}\n\n"

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
            err_msg = f"Audit failed: {str(e)}"
            yield f"data: {json.dumps({'event': 'error', 'message': err_msg, 'trace': traceback.format_exc()})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/export/html")
async def export_html_endpoint(summary: Dict[str, Any]):
    """Exports interactive standalone HTML file from summary data."""
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
        raise HTTPException(status_code=400, detail=f"Export failed: {e}")
