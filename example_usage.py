"""Example usage for EnterpriseIdentityTokenExchangeBridge."""
import sys
import json
from client import EnterpriseIdentityTokenExchangeBridge

sys.stdout.reconfigure(encoding='utf-8')

def main():
    print("=== Enterprise Cross-System Identity & Token Exchange Bridge Demo ===")
    bridge = EnterpriseIdentityTokenExchangeBridge()

    # 1. Exchange user identity into on-behalf-of delegated token for agent
    print("\n--- 1. Issuing On-Behalf-Of Token for WorkBuddy Agent ---")
    token = bridge.exchange_token_on_behalf_of(
        subject_user_id="zhangsan_wechat_work_99",
        agent_id="workbuddy_slide_compiler",
        target_service="TENCENT_DOCS",
        requested_scopes=["docs:export", "docs:read_tables"],
        ttl_seconds=3600
    )
    print("Delegated Token Details:")
    print(json.dumps(token, indent=2))

    # 2. Target service validates token and permissions
    print("\n--- 2. Validating Scoped Access at Tencent Docs Service ---")
    val_ok = bridge.validate_token_access(token["delegated_token"], "TENCENT_DOCS", "docs:export")
    print(f"Docs Access Permitted: {val_ok['valid']} (Remaining TTL: {val_ok.get('remaining_seconds')}s)")

    # 3. Test privilege escalation rejection
    print("\n--- 3. Testing Privilege Escalation Rejection (HR Payroll) ---")
    val_fail = bridge.validate_token_access(token["delegated_token"], "HR_PAYROLL", "payroll:read")
    print(f"Payroll Access Permitted: {val_fail['valid']} (Reason: {val_fail['reason']})")

if __name__ == "__main__":
    main()
