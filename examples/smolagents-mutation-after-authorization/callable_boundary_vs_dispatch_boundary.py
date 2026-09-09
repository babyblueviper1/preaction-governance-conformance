#!/usr/bin/env python3
"""Callable-boundary vs. dispatch-boundary guard placement — smolagents#2117
(Brodin2001's 2026-09-09 proposal: test whether AgentGuard's coverage model
survives across ToolCallingAgent's execute_tool_call() dispatch and
CodeAgent's direct-callable dispatch, rather than reasoning about it).

This doesn't wrap the real AgentGuard (that's Brodin2001's own library, kept
isolated per his own proposal) or import real smolagents. It's a minimal,
runnable simulation of the two dispatch shapes traced in agents.py, testing
the actual claim from the prior comment: a guard wired at a DISPATCH METHOD
(execute_tool_call-shaped) misses any call that never goes through that
method, but a guard wired at the CALLABLE ITSELF (wrapping the tool object
before either dispatch shape can reach it) catches both.

Real invinoveritas mechanism this borrows: action_binding's hash-recompute
check, reused here as `guard(tool_name, args, agent_id)` -- the point under
test is WHERE that check gets attached, not the check's own hash logic
(already covered in the sibling `action_binding_recompute.py`).
"""
import hashlib
import json


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuthorizationDenied(Exception):
    pass


class ActionBindingGuard:
    """Minimal recompute guard: authorize() records the hash of an exact
    (tool, args, agent_id) call; check() recomputes the same hash over an
    attempted call and raises if it doesn't match the last authorization.
    This is deliberately dumb (single last-authorization slot, no replay
    ledger) -- the point under test is placement, not the check's own
    sophistication, which the other example already covers."""

    def __init__(self):
        self._authorized_hash = None

    def _hash(self, tool_name: str, args: dict, agent_id: str) -> str:
        return hashlib.sha256(jcs({"tool": tool_name, "args": args, "agent_id": agent_id})).hexdigest()

    def authorize(self, tool_name: str, args: dict, agent_id: str) -> None:
        self._authorized_hash = self._hash(tool_name, args, agent_id)

    def check(self, tool_name: str, args: dict, agent_id: str) -> None:
        if self._authorized_hash is None or self._hash(tool_name, args, agent_id) != self._authorized_hash:
            raise AuthorizationDenied(f"unauthorized call: {tool_name}({args}) as {agent_id}")


def real_refund_tool(customer: str, amount: int) -> str:
    """The actual side-effecting callable -- a stand-in for a real Tool's
    forward()/`__call__`. This is what smolagents ultimately invokes,
    whichever dispatch shape got there."""
    return f"refunded {amount} to {customer}"


class ToolCallingAgentStyleDispatch:
    """Mirrors ToolCallingAgent.execute_tool_call() (agents.py:1453): ONE
    named dispatch method every call is required to pass through."""

    def __init__(self, tools: dict):
        self.tools = tools

    def execute_tool_call(self, tool_name: str, args: dict, agent_id: str) -> str:
        return self.tools[tool_name](**args)


class CodeAgentStyleDispatch:
    """Mirrors CodeAgent's real path (agents.py:492, 1726): tools handed
    directly into a namespace as plain callables, invoked by generated code
    as ordinary Python function calls -- no dispatch method exists to hook."""

    def __init__(self, tools: dict):
        self.namespace = dict(tools)  # send_tools()-equivalent

    def run_generated_code(self, tool_name: str, args: dict) -> str:
        # Equivalent of the LLM's generated code calling `refund(...)` directly.
        return self.namespace[tool_name](**args)


def guard_at_dispatch_method(guard: ActionBindingGuard, tools: dict) -> tuple:
    """VULNERABLE placement: wrap execute_tool_call() only."""
    tc_dispatch = ToolCallingAgentStyleDispatch(tools)
    original = tc_dispatch.execute_tool_call

    def guarded_execute_tool_call(tool_name, args, agent_id):
        guard.check(tool_name, args, agent_id)
        return original(tool_name, args, agent_id)

    tc_dispatch.execute_tool_call = guarded_execute_tool_call
    code_dispatch = CodeAgentStyleDispatch(tools)  # unguarded -- nothing wraps this path
    return tc_dispatch, code_dispatch


def guard_at_callable_boundary(guard: ActionBindingGuard, tools: dict, agent_id_for_wrap: str) -> tuple:
    """FIXED placement: wrap each TOOL CALLABLE itself, once, before either
    dispatch mechanism ever gets a reference to it -- mirrors wrapping at
    send_tools()'s input, not at a dispatch method only one subclass has."""

    def wrap(name, fn):
        def guarded(**kwargs):
            guard.check(name, kwargs, agent_id_for_wrap)
            return fn(**kwargs)
        return guarded

    guarded_tools = {name: wrap(name, fn) for name, fn in tools.items()}
    tc_dispatch = ToolCallingAgentStyleDispatch(guarded_tools)
    code_dispatch = CodeAgentStyleDispatch(guarded_tools)
    return tc_dispatch, code_dispatch


def main() -> None:
    tools = {"refund": real_refund_tool}
    baseline = dict(tool_name="refund", args={"customer": "A", "amount": 100}, agent_id="support-agent-1")

    print("=== Placement 1: guard wired at execute_tool_call() (the obvious place) ===")
    guard1 = ActionBindingGuard()
    guard1.authorize(**baseline)
    tc1, code1 = guard_at_dispatch_method(guard1, tools)

    # Authorized call via ToolCallingAgent-style dispatch: allowed.
    result = tc1.execute_tool_call("refund", {"customer": "A", "amount": 100}, "support-agent-1")
    print(f"  ToolCallingAgent-style, authorized call: OK -> {result}")

    # Mutated call via the SAME dispatch: correctly denied.
    try:
        tc1.execute_tool_call("refund", {"customer": "A", "amount": 1000}, "support-agent-1")
        print("  FAIL: mutated call via ToolCallingAgent-style dispatch was NOT denied")
    except AuthorizationDenied:
        print("  ToolCallingAgent-style, mutated call: correctly DENIED")

    # The SAME mutated call via CodeAgent-style dispatch: bypasses the guard entirely.
    bypassed = code1.run_generated_code("refund", {"customer": "A", "amount": 1000})
    print(f"  CodeAgent-style, SAME mutated call: NOT DENIED -- bypass confirmed -> {bypassed}")
    assert bypassed == "refunded 1000 to A", "expected the bypass to actually execute unauthorized"

    print()
    print("=== Placement 2: guard wired at the callable boundary itself (the fix) ===")
    guard2 = ActionBindingGuard()
    guard2.authorize(**baseline)
    tc2, code2 = guard_at_callable_boundary(guard2, tools, agent_id_for_wrap="support-agent-1")

    result = tc2.execute_tool_call("refund", {"customer": "A", "amount": 100}, "support-agent-1")
    print(f"  ToolCallingAgent-style, authorized call: OK -> {result}")

    try:
        tc2.execute_tool_call("refund", {"customer": "A", "amount": 1000}, "support-agent-1")
        print("  FAIL: mutated call via ToolCallingAgent-style dispatch was NOT denied")
    except AuthorizationDenied:
        print("  ToolCallingAgent-style, mutated call: correctly DENIED")

    # The SAME mutated call attempted via CodeAgent-style dispatch: now ALSO denied,
    # because the guard lives on the callable, not on a dispatch method either
    # subclass may or may not call through.
    try:
        code2.run_generated_code("refund", {"customer": "A", "amount": 1000})
        print("  FAIL: mutated call via CodeAgent-style dispatch was NOT denied")
    except AuthorizationDenied:
        print("  CodeAgent-style, SAME mutated call: correctly DENIED -- bypass closed")

    # Confirm the authorized call still works via CodeAgent-style dispatch too
    # (the fix must not break the legitimate path).
    ok = code2.run_generated_code("refund", {"customer": "A", "amount": 100})
    print(f"  CodeAgent-style, authorized call: OK -> {ok}")

    print()
    print("Result: wrapping execute_tool_call() gives the ToolCallingAgent-style path")
    print("full protection and the CodeAgent-style path NONE -- a real, demonstrated bypass,")
    print("not a hypothetical one. Wrapping the callable itself, once, before either dispatch")
    print("mechanism receives a reference to it, protects both -- confirming the fix proposed")
    print("in the prior comment (hook at the tool/managed-agent object boundary, not at a")
    print("dispatch method only one agent subclass happens to call through).")


if __name__ == "__main__":
    main()
