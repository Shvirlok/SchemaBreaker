"""Schema and System Prompt Loader for SchemaBreaker."""

import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, Union
from pydantic import BaseModel, create_model

from schemabreaker.demo import DEMO_REGISTRY, get_demo_schema


class SchemaInspector:
    """Introspects and serializes Pydantic schemas for LLM and user analysis."""

    def __init__(self, model_class: Type[BaseModel], system_prompt: Optional[str] = None, source_code: Optional[str] = None):
        self.model_class = model_class
        self.system_prompt = system_prompt or "Extract structured data from the input matching the target schema."
        self.source_code = source_code
        self._json_schema: Optional[Dict[str, Any]] = None

    @property
    def model_name(self) -> str:
        return self.model_class.__name__

    @property
    def json_schema(self) -> Dict[str, Any]:
        if self._json_schema is None:
            self._json_schema = self.model_class.model_json_schema()
        return self._json_schema

    def _extract_constraints(self, field_info: Any) -> Dict[str, Any]:
        """Safely extracts validation constraints and pattern from FieldInfo and its metadata."""
        constraints = {}
        for attr in ["gt", "ge", "lt", "le", "min_length", "max_length", "pattern"]:
            val = getattr(field_info, attr, None)
            if val is not None:
                constraints[attr] = val
        for m in getattr(field_info, "metadata", []):
            for attr in ["gt", "ge", "lt", "le", "min_length", "max_length", "pattern"]:
                if hasattr(m, attr):
                    val = getattr(m, attr)
                    if val is not None:
                        constraints[attr] = val
        return constraints

    def get_summary_text(self) -> str:
        """Returns a human and LLM-friendly structural summary of the schema."""
        lines = [f"### Target Pydantic Schema: `{self.model_name}`"]
        if self.model_class.__doc__:
            lines.append(f"Description: {self.model_class.__doc__.strip()}")
        lines.append("")
        lines.append("#### Fields & Constraints:")

        def inspect_model(cls: Type[BaseModel], prefix: str = "", depth: int = 0):
            if depth > 4:
                return
            for field_name, field_info in cls.model_fields.items():
                req_str = "REQUIRED" if field_info.is_required() else f"OPTIONAL (default={field_info.default})"
                type_name = str(field_info.annotation)
                # Clean up type name representation
                type_name = type_name.replace("typing.", "").replace("<class '", "").replace("'>", "")
                desc = f" - {field_info.description}" if field_info.description else ""

                c_map = self._extract_constraints(field_info)
                constraint_items = [f"{k}={v}" for k, v in c_map.items()]
                constraint_str = f" [{', '.join(constraint_items)}]" if constraint_items else ""

                lines.append(f"{prefix}* `{field_name}`: `{type_name}` ({req_str}){constraint_str}{desc}")

                # Check for nested submodels or enums
                annotation = field_info.annotation
                nested_cls = None
                if inspect.isclass(annotation) and issubclass(annotation, BaseModel):
                    nested_cls = annotation
                elif hasattr(annotation, "__args__"):
                    for arg in annotation.__args__:
                        if inspect.isclass(arg) and issubclass(arg, BaseModel):
                            nested_cls = arg
                            break

                if nested_cls and nested_cls != cls:
                    lines.append(f"{prefix}    ↳ Nested Schema `{nested_cls.__name__}`:")
                    inspect_model(nested_cls, prefix=prefix + "      ", depth=depth + 1)

        inspect_model(self.model_class)
        return "\n".join(lines)

    def get_enums_and_patterns(self) -> Dict[str, Any]:
        """Extracts all enum choices and regex patterns for targeted fuzzing."""
        enums: Dict[str, List[str]] = {}
        patterns: Dict[str, str] = {}
        ranges: Dict[str, Dict[str, Any]] = {}

        def walk(cls: Type[BaseModel], path_prefix: str = ""):
            for field_name, field_info in cls.model_fields.items():
                full_path = f"{path_prefix}{field_name}"
                ann = field_info.annotation
                if ann is not None and hasattr(ann, "__members__"):
                    enums[full_path] = list(ann.__members__.keys())
                elif hasattr(ann, "__args__"):
                    for arg in getattr(ann, "__args__", ()):
                        if hasattr(arg, "__members__"):
                            enums[full_path] = list(arg.__members__.keys())

                c_map = self._extract_constraints(field_info)
                if "pattern" in c_map:
                    patterns[full_path] = c_map["pattern"]

                num_bounds = {k: v for k, v in c_map.items() if k != "pattern"}
                if num_bounds:
                    ranges[full_path] = num_bounds

                nested = None
                if inspect.isclass(ann) and issubclass(ann, BaseModel):
                    nested = ann
                elif hasattr(ann, "__args__"):
                    for arg in ann.__args__:
                        if inspect.isclass(arg) and issubclass(arg, BaseModel):
                            nested = arg
                            break
                if nested and nested != cls:
                    walk(nested, path_prefix=f"{full_path}.")

        walk(self.model_class)
        return {
            "enums": enums,
            "patterns": patterns,
            "ranges": ranges,
        }


def load_schema_from_path(
    path_or_demo: str,
    model_name: Optional[str] = None,
    system_prompt_path: Optional[str] = None,
    system_prompt_text: Optional[str] = None,
) -> SchemaInspector:
    """
    Load a Pydantic schema from:
    1. A built-in demo key ('ecommerce', 'clinical', 'financial')
    2. A Python file path ('path/to/file.py' or 'path/to/file.py:ModelName')
    3. A JSON Schema file ('path/to/schema.json')
    """
    prompt = system_prompt_text
    if system_prompt_path and Path(system_prompt_path).exists():
        prompt = Path(system_prompt_path).read_text(encoding="utf-8")

    # Check if demo name
    if path_or_demo in DEMO_REGISTRY:
        model_cls, default_prompt, _ = get_demo_schema(path_or_demo)
        return SchemaInspector(
            model_class=model_cls,
            system_prompt=prompt or default_prompt,
            source_code=f"# Loaded from built-in demo: {path_or_demo}\n# Class: {model_cls.__name__}"
        )

    # Handle path:ModelName format
    file_path = path_or_demo
    target_model_name = model_name
    if ":" in path_or_demo and not path_or_demo.endswith(".json"):
        parts = path_or_demo.split(":", 1)
        file_path = parts[0]
        target_model_name = parts[1]

    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found at: {path}")

    # JSON Schema loader
    if path.suffix.lower() == ".json":
        raw_json = path.read_text(encoding="utf-8")
        data = json.loads(raw_json)
        model_cls = _create_model_from_json_schema(data, model_name=target_model_name or "DynamicJsonModel")
        return SchemaInspector(
            model_class=model_cls,
            system_prompt=prompt or "Parse user request according to the JSON schema.",
            source_code=raw_json
        )

    # Python file loader
    if path.suffix.lower() == ".py":
        code = path.read_text(encoding="utf-8")
        model_cls, inferred_prompt = _load_pydantic_from_py_file(path, target_model_name)
        return SchemaInspector(
            model_class=model_cls,
            system_prompt=prompt or inferred_prompt or "Extract structured information.",
            source_code=code
        )

    raise ValueError(f"Unsupported file type: {path.suffix}. Expected .py or .json")


def load_schema_from_code(
    code_str: str,
    model_name: Optional[str] = None,
    system_prompt: Optional[str] = None,
) -> SchemaInspector:
    """Dynamically executes Python code string and extracts the specified or largest Pydantic model."""
    scope: Dict[str, Any] = {}
    exec(code_str, scope)

    candidates = [
        obj for name, obj in scope.items()
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj != BaseModel
    ]

    if not candidates:
        raise ValueError("No Pydantic BaseModel subclasses found in the provided code snippet.")

    selected_model: Type[BaseModel]
    if model_name:
        matched = [c for c in candidates if c.__name__ == model_name]
        if not matched:
            avail = [c.__name__ for c in candidates]
            raise ValueError(f"Model '{model_name}' not found. Available models: {avail}")
        selected_model = matched[0]
    else:
        # Choose the model that references others or has the most fields
        selected_model = max(candidates, key=lambda m: len(m.model_fields))

    inferred_prompt = scope.get("SYSTEM_PROMPT") or scope.get("system_prompt")
    return SchemaInspector(
        model_class=selected_model,
        system_prompt=system_prompt or (str(inferred_prompt) if inferred_prompt else None),
        source_code=code_str
    )


def _load_pydantic_from_py_file(
    file_path: Path,
    model_name: Optional[str] = None
) -> Tuple[Type[BaseModel], Optional[str]]:
    """Imports a python file as a module and returns (ModelClass, SystemPrompt)."""
    module_name = f"schemabreaker_loaded_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if not spec or not spec.loader:
        raise ImportError(f"Could not load module from {file_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    candidates = [
        obj for name, obj in inspect.getmembers(module, inspect.isclass)
        if issubclass(obj, BaseModel) and obj != BaseModel and obj.__module__ == module_name
    ]

    if not candidates:
        # Fallback to any BaseModel subclass defined in the module
        candidates = [
            obj for name, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, BaseModel) and obj != BaseModel
        ]

    if not candidates:
        raise ValueError(f"No Pydantic BaseModel found in {file_path}")

    if model_name:
        matched = [c for c in candidates if c.__name__ == model_name]
        if not matched:
            avail = [c.__name__ for c in candidates]
            raise ValueError(f"Model '{model_name}' not found in {file_path}. Found: {avail}")
        model_cls = matched[0]
    else:
        model_cls = max(candidates, key=lambda m: len(m.model_fields))

    system_prompt = getattr(module, "SYSTEM_PROMPT", None) or getattr(module, "system_prompt", None)
    return model_cls, str(system_prompt) if system_prompt else None


def _create_model_from_json_schema(schema_dict: Dict[str, Any], model_name: str = "JsonSchemaModel") -> Type[BaseModel]:
    """Generates a dynamic Pydantic v2 model from a JSON Schema dictionary."""
    properties = schema_dict.get("properties", {})
    required_fields = set(schema_dict.get("required", []))
    fields_dict: Dict[str, Tuple[Any, Any]] = {}

    type_mapping = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    for prop_name, prop_data in properties.items():
        json_type = prop_data.get("type", "string")
        if isinstance(json_type, list):
            json_type = json_type[0] if json_type else "string"

        py_type = type_mapping.get(json_type, Any)
        is_req = prop_name in required_fields
        default_val = ... if is_req else prop_data.get("default", None)
        fields_dict[prop_name] = (py_type if is_req else Optional[py_type], default_val)

    if not fields_dict:
        # Fallback if no properties defined
        fields_dict["data"] = (Dict[str, Any], ...)

    return create_model(model_name, **fields_dict)  # type: ignore
