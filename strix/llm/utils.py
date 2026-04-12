import html
import re
from typing import Any


_INVOKE_OPEN = re.compile(r'<invoke\s+name=["\']([^"\']+)["\']>')
_PARAM_NAME_ATTR = re.compile(r'<parameter\s+name=["\']?([^"\'>\s]+)["\']?\s*>')
_FUNCTION_CALLS_TAG = re.compile(r"</?function_calls>")
_STRIP_TAG_QUOTES = re.compile(r"<(function|parameter)\s*=\s*([^>]*?)>")
# MiniMax M2.7 broken format: <parameter=="VALUE"</parameter>
# Parameter name is missing — extract value, mark as positional (__pos_N__)
_MINIMAX_BROKEN_PARAM = re.compile(r'<parameter==["\']?([^"\'<>\n]+?)["\']?\s*</parameter>')


def normalize_tool_format(content: str) -> str:
    """Convert alternative tool-call XML formats to the expected one.

    Handles:
      <function_calls>...</function_calls>  → stripped
      <invoke name="X">                     → <function=X>
      <parameter name="X">                  → <parameter=X>
      </invoke>                             → </function>
      <function="X">                        → <function=X>
      <parameter="X">                       → <parameter=X>
      <parameter=="VALUE"</parameter>       → <parameter=__pos_N__>VALUE</parameter>  (MiniMax M2.7)
    """
    # MiniMax M2.7: fix broken <parameter=="VALUE"</parameter> before other transforms
    if "<parameter==" in content:
        counter = [0]
        def _replace_broken(m: re.Match) -> str:  # noqa: ANN001
            idx = counter[0]
            counter[0] += 1
            return f"<parameter=__pos_{idx}__>{m.group(1).strip()}</parameter>"
        content = _MINIMAX_BROKEN_PARAM.sub(_replace_broken, content)

    if "<invoke" in content or "<function_calls" in content:
        content = _FUNCTION_CALLS_TAG.sub("", content)
        content = _INVOKE_OPEN.sub(r"<function=\1>", content)
        content = content.replace("</invoke>", "</function>")

    # Always normalize <parameter name="X"> → <parameter=X> (not just inside invoke blocks)
    if '<parameter name=' in content or '<parameter  name=' in content:
        content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)

    return _STRIP_TAG_QUOTES.sub(
        lambda m: f"<{m.group(1)}={m.group(2).strip().strip(chr(34) + chr(39))}>", content
    )


STRIX_MODEL_MAP: dict[str, str] = {
    "claude-sonnet-4.6": "anthropic/claude-sonnet-4-6",
    "claude-opus-4.6": "anthropic/claude-opus-4-6",
    "gpt-5.2": "openai/gpt-5.2",
    "gpt-5.1": "openai/gpt-5.1",
    "gpt-5.4": "openai/gpt-5.4",
    "gemini-3-pro-preview": "gemini/gemini-3-pro-preview",
    "gemini-3-flash-preview": "gemini/gemini-3-flash-preview",
    "glm-5": "openrouter/z-ai/glm-5",
    "glm-4.7": "openrouter/z-ai/glm-4.7",
}


def resolve_strix_model(model_name: str | None) -> tuple[str | None, str | None]:
    """Resolve a strix/ model into names for API calls and capability lookups.

    Returns (api_model, canonical_model):
    - api_model: openai/<base> for API calls (Strix API is OpenAI-compatible)
    - canonical_model: actual provider model name for litellm capability lookups
    Non-strix models return the same name for both.
    """
    if not model_name or not model_name.startswith("strix/"):
        return model_name, model_name

    base_model = model_name[6:]
    api_model = f"openai/{base_model}"
    canonical_model = STRIX_MODEL_MAP.get(base_model, api_model)
    return api_model, canonical_model


def _truncate_to_first_function(content: str) -> str:
    if not content:
        return content

    function_starts = [
        match.start() for match in re.finditer(r"<function=|<invoke\s+name=", content)
    ]

    if len(function_starts) >= 2:
        second_function_start = function_starts[1]

        return content[:second_function_start].rstrip()

    return content


def _resolve_positional_args(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Map __pos_N__ keys (from MiniMax M2.7 broken format) to actual param names.

    Tries XML schema first, falls back to Python function signature inspection.
    """
    positional_keys = sorted(k for k in args if k.startswith("__pos_") and k.endswith("__"))
    if not positional_keys:
        return args

    unfilled_required: list[str] = []
    try:
        from strix.tools.registry import get_tool_by_name, get_tool_param_schema  # lazy import
        import inspect as _inspect

        schema = get_tool_param_schema(tool_name)
        if schema and schema.get("has_params") and schema.get("required"):
            # Schema available and parsed correctly
            required = sorted(schema["required"])
            unfilled_required = [p for p in required if p not in args or args[p] in (None, "")]
        else:
            # Schema unavailable or empty — fall back to function signature inspection
            tool_func = get_tool_by_name(tool_name)
            if tool_func:
                sig = _inspect.signature(tool_func)
                unfilled_required = [
                    name for name, param in sig.parameters.items()
                    if name != "agent_state"
                    and param.default is _inspect.Parameter.empty
                    and name not in args
                ]
    except Exception:  # noqa: BLE001
        return args

    if not unfilled_required:
        return args

    resolved = {k: v for k, v in args.items() if not k.startswith("__pos_")}
    for pos_key, param_name in zip(positional_keys, unfilled_required):
        resolved[param_name] = args[pos_key]
    return resolved


def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_invocations: list[dict[str, Any]] = []

    fn_regex_pattern = r"<function=([^>]+)>\n?(.*?)</function>"
    fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"

    fn_matches = re.finditer(fn_regex_pattern, content, re.DOTALL)

    for fn_match in fn_matches:
        fn_name = fn_match.group(1)
        fn_body = fn_match.group(2)

        param_matches = re.finditer(fn_param_regex_pattern, fn_body, re.DOTALL)

        args = {}
        for param_match in param_matches:
            param_name = param_match.group(1)
            param_value = param_match.group(2).strip()

            param_value = html.unescape(param_value)
            args[param_name] = param_value

        args = _resolve_positional_args(fn_name, args)
        tool_invocations.append({"toolName": fn_name, "args": args})

    return tool_invocations if tool_invocations else None


def fix_incomplete_tool_call(content: str) -> str:
    """Fix incomplete tool calls by adding missing closing tag.

    Handles both ``<function=…>`` and ``<invoke name="…">`` formats.
    """
    has_open = "<function=" in content or "<invoke " in content
    count_open = content.count("<function=") + content.count("<invoke ")
    has_close = "</function>" in content or "</invoke>" in content
    if has_open and count_open == 1 and not has_close:
        content = content.rstrip()
        content = content + "function>" if content.endswith("</") else content + "\n</function>"
    return content


def format_tool_call(tool_name: str, args: dict[str, Any]) -> str:
    xml_parts = [f"<function={tool_name}>"]

    for key, value in args.items():
        xml_parts.append(f"<parameter={key}>{value}</parameter>")

    xml_parts.append("</function>")

    return "\n".join(xml_parts)


def clean_content(content: str) -> str:
    if not content:
        return ""

    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_pattern = r"<function=[^>]+>.*?</function>"
    cleaned = re.sub(tool_pattern, "", content, flags=re.DOTALL)

    incomplete_tool_pattern = r"<function=[^>]+>.*$"
    cleaned = re.sub(incomplete_tool_pattern, "", cleaned, flags=re.DOTALL)

    partial_tag_pattern = r"<f(?:u(?:n(?:c(?:t(?:i(?:o(?:n(?:=(?:[^>]*)?)?)?)?)?)?)?)?)?$"
    cleaned = re.sub(partial_tag_pattern, "", cleaned)

    hidden_xml_patterns = [
        r"<inter_agent_message>.*?</inter_agent_message>",
        r"<agent_completion_report>.*?</agent_completion_report>",
    ]
    for pattern in hidden_xml_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    cleaned = re.sub(r"\n\s*\n", "\n\n", cleaned)

    return cleaned.strip()
