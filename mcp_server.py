"""MCP Server for Enterprise Identity Token Exchange Bridge."""
import sys
import json
import time
from client import EnterpriseIdentityTokenExchangeBridge

bridge = EnterpriseIdentityTokenExchangeBridge()

def handle_call_tool(params):
    name = params.get("name")
    args = params.get("arguments", {})
    if name != "exchange_enterprise_identity_token":
        raise ValueError(f"Unknown tool: {name}")

    action = args.get("action", "exchange_token_on_behalf_of")
    if action == "exchange_token_on_behalf_of":
        return bridge.exchange_token_on_behalf_of(
            subject_user_id=args.get("subject_user_id", "user_1"),
            agent_id=args.get("agent_id", "workbuddy_agent_1"),
            target_service=args.get("target_service", "TENCENT_DOCS"),
            requested_scopes=args.get("requested_scopes", ["read"]),
            ttl_seconds=int(args.get("ttl_seconds", 3600))
        )
    elif action == "validate_token_access":
        return bridge.validate_token_access(
            token_string=args.get("token_string", ""),
            required_service=args.get("target_service", ""),
            required_scope=args.get("requested_scopes", [None])[0] if args.get("requested_scopes") else None
        )
    elif action == "refresh_token":
        return bridge.refresh_token(args.get("token_string", ""))
    elif action == "revoke_token":
        return bridge.revoke_token(args.get("token_string", ""))
    elif action == "get_active_sessions":
        return bridge.get_active_sessions()
    else:
        raise ValueError(f"Invalid action: {action}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Running self-test...")
        tok = bridge.exchange_token_on_behalf_of("emp_101", "ppt_agent", "TENCENT_DOCS", ["docs:read", "docs:write"], 1800)
        assert tok["delegated_token"].startswith("GP-OBO.")
        val = bridge.validate_token_access(tok["delegated_token"], "TENCENT_DOCS", "docs:read")
        assert val["valid"] is True
        bad_val = bridge.validate_token_access(tok["delegated_token"], "FINANCIAL_LEDGER")
        assert bad_val["valid"] is False
        print("Self-test PASSED!")
        sys.exit(0)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            msg_id = req.get("id")
            method = req.get("method")
            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "EnterpriseIdentityTokenExchangeBridge", "version": "1.0.0"},
                        "capabilities": {"tools": {}}
                    }
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [{
                            "name": "exchange_enterprise_identity_token",
                            "description": "Enterprise identity token exchange: issue on-behalf-of delegated tokens, validate scope boundaries, refresh expired tokens, and revoke credentials.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "action": {"type": "string", "enum": ["exchange_token_on_behalf_of", "validate_token_access", "refresh_token", "revoke_token", "get_active_sessions"]},
                                    "subject_user_id": {"type": "string"},
                                    "agent_id": {"type": "string"},
                                    "target_service": {"type": "string"},
                                    "requested_scopes": {"type": "array"},
                                    "token_string": {"type": "string"},
                                    "ttl_seconds": {"type": "integer"}
                                },
                                "required": ["action"]
                            }
                        }]
                    }
                }
            elif method == "tools/call":
                res = handle_call_tool(req.get("params", {}))
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
                }
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            print(json.dumps(resp), flush=True)
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(e)}}
            print(json.dumps(err_resp), flush=True)

if __name__ == "__main__":
    main()
