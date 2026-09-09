#!/usr/bin/env python3
"""Runs Brodin2001's real AgentGuard (v0.2-action-bound-authorization,
github.com/Brodin2001/Agentguard) through the same two dispatch placements
already tested against invinoveritas's own action_binding-shaped check:
execute_tool_call()-style dispatch boundary vs. callable boundary.

Setup: pip install "git+https://github.com/Brodin2001/Agentguard.git@v0.2-action-bound-authorization"
(not vendored here -- no LICENSE file in that repo as of this branch, so the
source isn't redistributed, only imported).

Per the requester's own instruction: if it fails anywhere, the failure is
left intact, not adapted around.
"""
from agentguard import AgentGuard

POLICIES = {"execution": {"allowed_tools": ["refund"], "argument_rules": {}}}


def real_refund_tool(customer: str, amount: int) -> str:
    return f"refunded {amount} to {customer}"


BASELINE_ARGS = {"customer": "customer-123", "amount": 100}
MUTATED_ARGS = {"customer": "customer-123", "amount": 1000}
BASELINE_CTX = dict(target="customer-123", agent_id="agent-1", runtime_id="run-1")


def section(title):
    print(f"\n=== {title} ===")


def main() -> None:
    guard = AgentGuard(POLICIES)

    section("Placement 1: guard wired at execute_tool_call() (dispatch boundary)")
    receipt1 = guard.issue_receipt(state="execution", tool="refund", arguments=BASELINE_ARGS, **BASELINE_CTX)

    class ToolCallingAgentStyleDispatch:
        """Mirrors ToolCallingAgent.execute_tool_call(): the ONE method every
        call is required to pass through, and the ONLY place AgentGuard is wired in."""
        def execute_tool_call(self, tool_name, args, receipt):
            fn = {"refund": real_refund_tool}[tool_name]
            return guard.execute_receipt(receipt, fn, arguments=args, **BASELINE_CTX)

    class CodeAgentStyleDispatch:
        """Mirrors CodeAgent: tools are plain callables in a generated-code
        namespace. AgentGuard's own docstring says it plainly: 'Alternate
        direct calls to the underlying function remain outside this
        library's control boundary.' This class IS that alternate path."""
        def __init__(self):
            self.namespace = {"refund": real_refund_tool}  # raw, unguarded

        def run_generated_code(self, tool_name, args):
            return self.namespace[tool_name](**args)

    tc = ToolCallingAgentStyleDispatch()
    code = CodeAgentStyleDispatch()

    mutated_via_tc = tc.execute_tool_call("refund", MUTATED_ARGS, receipt1)
    print(f"  ToolCallingAgent-style, mutated call: allowed={mutated_via_tc['allowed']} "
          f"({mutated_via_tc['reason']})")
    assert mutated_via_tc["allowed"] is False, "expected AgentGuard to deny the mutated call here"

    bypassed = code.run_generated_code("refund", MUTATED_ARGS)
    print(f"  CodeAgent-style, SAME mutated call, direct callable (no guard involved): "
          f"executed -> {bypassed!r}")
    assert bypassed == "refunded 1000 to customer-123", "expected the bypass to actually execute"

    authorized_via_tc = tc.execute_tool_call("refund", BASELINE_ARGS, receipt1)
    print(f"  ToolCallingAgent-style, authorized call (same still-unconsumed receipt): "
          f"executed={authorized_via_tc['executed']} -> {authorized_via_tc.get('result')}")
    assert authorized_via_tc["executed"] is True

    replay_via_tc = tc.execute_tool_call("refund", BASELINE_ARGS, receipt1)
    print(f"  ToolCallingAgent-style, REPLAY of the same authorized call: "
          f"allowed={replay_via_tc['allowed']} ({replay_via_tc['reason']})")
    assert replay_via_tc["allowed"] is False, "expected replay to be denied (receipt already consumed)"

    section("Placement 2: guard wired at the callable boundary itself (the fix)")
    receipt2 = guard.issue_receipt(state="execution", tool="refund", arguments=BASELINE_ARGS, **BASELINE_CTX)

    def wrap_with_agentguard(fn, receipt):
        """Wraps the CALLABLE ITSELF with AgentGuard's real execute_receipt,
        before either dispatch mechanism gets a reference to it. Context
        (target/agent_id/runtime_id) is bound from the receipt's own trusted
        values at wrap time, not taken from caller-supplied kwargs -- an
        attacker controls `arguments`, not the wrapper's own closure."""
        def guarded(**kwargs):
            result = guard.execute_receipt(receipt, fn, arguments=kwargs, **BASELINE_CTX)
            if not result["allowed"]:
                raise PermissionError(result["reason"])
            if not result.get("executed"):
                raise RuntimeError(result.get("error", "execution failed"))
            return result["result"]
        return guarded

    guarded_refund = wrap_with_agentguard(real_refund_tool, receipt2)

    class ToolCallingAgentStyleDispatch2:
        def __init__(self, tools):
            self.tools = tools

        def execute_tool_call(self, tool_name, args):
            return self.tools[tool_name](**args)

    class CodeAgentStyleDispatch2:
        def __init__(self, tools):
            self.namespace = dict(tools)

        def run_generated_code(self, tool_name, args):
            return self.namespace[tool_name](**args)

    guarded_tools = {"refund": guarded_refund}
    tc2 = ToolCallingAgentStyleDispatch2(guarded_tools)
    code2 = CodeAgentStyleDispatch2(guarded_tools)

    try:
        tc2.execute_tool_call("refund", MUTATED_ARGS)
        print("  FAIL: mutated call via ToolCallingAgent-style dispatch was NOT denied")
    except PermissionError as e:
        print(f"  ToolCallingAgent-style, mutated call: correctly DENIED ({e})")

    try:
        code2.run_generated_code("refund", MUTATED_ARGS)
        print("  FAIL: mutated call via CodeAgent-style dispatch was NOT denied")
    except PermissionError as e:
        print(f"  CodeAgent-style, SAME mutated call: correctly DENIED ({e}) -- bypass closed")

    ok = code2.run_generated_code("refund", BASELINE_ARGS)
    print(f"  CodeAgent-style, authorized call (same still-unconsumed receipt): OK -> {ok!r}")

    try:
        code2.run_generated_code("refund", BASELINE_ARGS)
        print("  FAIL: replay via CodeAgent-style dispatch was NOT denied")
    except PermissionError as e:
        print(f"  CodeAgent-style, REPLAY of the authorized call: correctly DENIED ({e})")

    print()
    print("Classification: what AgentGuard's OWN guard.execute_receipt() caught vs. what the")
    print("framework/existing-guard-shape caught, as requested --")
    print("  * Mutation, replay, and (untested here but present in the code) expiry and")
    print("    policy-staleness are all caught by AgentGuard's verify_and_consume() ITSELF,")
    print("    whichever placement calls it -- these are receipt-shape properties, not")
    print("    placement-dependent.")
    print("  * Whether verify_and_consume() gets called AT ALL for a given call site is")
    print("    entirely a placement question -- AgentGuard's own docstring already says so")
    print("    plainly ('Alternate direct calls ... remain outside this library's control")
    print("    boundary'). This harness reproduces that disclosed limitation concretely against")
    print("    a real CodeAgent-shaped call, and confirms wrapping the callable (not the")
    print("    dispatch method) closes it using AgentGuard's real API, not a toy substitute.")
    print("  * One capability AgentGuard has that our own action_binding-shaped check in the")
    print("    prior fixture does NOT: real TTL-based expiry and live policy-hash re-verification")
    print("    at consume time (our own disclosed gap, see full_receipt_adversarial_matrix.py).")


if __name__ == "__main__":
    main()
