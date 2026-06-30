from llamafirewall import LlamaFirewall, Role, ScannerType, UserMessage, ToolMessage, AssistantMessage, ScanDecision

class GuardrailEngine:
    def __init__(self, lf: LlamaFirewall, inv_rules: list):
        self._lf = lf
        self._inv = inv_rules
        self._call_trace = collections.deque(maxlen=64)  # Invariant toxic flow 窗口

    async def check_request(self, *, method, service_names, tool_name, params, headers):
        # 1) LlamaFirewall：tools/call 的 arguments 作为 TOOL 角色扫描
        args_text = json.dumps(params.get("arguments", {}))
        lf_res = await self._lf.scan_async(ToolMessage(content=args_text))
        if lf_res.decision == ScanDecision.BLOCK:
            return Decision(deny=True, reason=f"LF:block:{lf_res.scanner}")
        # 2) Invariant：记录 tool_call 进 trace，匹配 toxic flow
        self._call_trace.append({"tool": tool_name, "args": params.get("arguments", {})})
        for rule in self._inv:
            hit = rule.match(self._call_trace)
            if hit:
                return Decision(deny=True, reason=f"INV:{rule.name}")
        # 3) 隐藏 ASCII / PII 可在此追加
        return Decision(deny=False)

    async def check_response(self, *, method, service_names, result):
        # 间接注入核心防线：工具返回内容作为 ASSISTANT 角色过 PromptGuard
        content = json.dumps(result.get("content", result))
        lf_res = await self._lf.scan_async(AssistantMessage(content=content))
        if lf_res.decision == ScanDecision.BLOCK:
            return Decision(deny=True, reason=f"LF:indirect_injection")
        return Decision(deny=False)
