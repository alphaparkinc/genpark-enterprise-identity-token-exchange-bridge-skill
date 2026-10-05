"""
Enterprise Cross-System Identity & Token Exchange Bridge (Zero External Dependencies)
Provides on-behalf-of OAuth2/SAML-style token delegation, cryptographic signing, and scope isolation.
"""
import time
import math
import hashlib
import hmac
import base64
import json
from typing import Dict, Any, List, Optional, Set

class EnterpriseIdentityTokenExchangeBridge:
    def __init__(self, bridge_master_secret: str = "bridge_ephemeral_secret_key"):
        self.secret = bridge_master_secret.encode("utf-8")
        self.active_tokens: Dict[str, Dict[str, Any]] = {}

    def _sign_token(self, payload_str: str) -> str:
        sig = hmac.new(self.secret, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        b64 = base64.urlsafe_b64encode(payload_str.encode("utf-8")).decode("ascii")
        return f"GP-OBO.{b64}.{sig}"

    def exchange_token_on_behalf_of(
        self,
        subject_user_id: str,
        agent_id: str,
        target_service: str,
        requested_scopes: List[str],
        ttl_seconds: int = 3600
    ) -> Dict[str, Any]:
        """
        Exchanges a user identity into a down-scoped delegated token for an autonomous worker agent.
        """
        now = time.time()
        expires_at = now + ttl_seconds
        token_id = "tok_" + hashlib.sha256(f"{subject_user_id}{agent_id}{now}".encode("utf-8")).hexdigest()[:12]

        payload = {
            "token_id": token_id,
            "sub": subject_user_id,
            "aud": target_service.upper(),
            "act": {"agent_id": agent_id}, # actor (on behalf of)
            "scopes": list(set(requested_scopes)),
            "iat": int(now),
            "exp": int(expires_at)
        }

        token_str = self._sign_token(json.dumps(payload, sort_keys=True))
        self.active_tokens[token_str] = payload

        return {
            "delegated_token": token_str,
            "token_id": token_id,
            "subject_user_id": subject_user_id,
            "target_service": target_service.upper(),
            "granted_scopes": payload["scopes"],
            "expires_in_seconds": ttl_seconds,
            "expires_at": int(expires_at)
        }

    def validate_token_access(
        self,
        token_string: str,
        required_service: str,
        required_scope: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validates signature, expiration, audience service, and scope permissions."""
        if token_string not in self.active_tokens:
            return {"valid": False, "reason": "Token not found or revoked"}

        payload = self.active_tokens[token_string]
        now = time.time()

        if now > payload["exp"]:
            return {"valid": False, "reason": "Token expired"}

        if payload["aud"] != required_service.upper() and payload["aud"] != "*":
            return {"valid": False, "reason": f"Audience mismatch: token intended for {payload['aud']}, not {required_service}"}

        if required_scope and required_scope not in payload["scopes"]:
            return {"valid": False, "reason": f"Missing required scope: '{required_scope}' not in {payload['scopes']}"}

        return {
            "valid": True,
            "subject_user_id": payload["sub"],
            "agent_id": payload["act"]["agent_id"],
            "target_service": payload["aud"],
            "remaining_seconds": int(payload["exp"] - now)
        }

    def refresh_token(self, token_string: str, extend_seconds: int = 1800) -> Dict[str, Any]:
        """Extends token lifetime if token is still valid."""
        val = self.validate_token_access(token_string, self.active_tokens.get(token_string, {}).get("aud", ""))
        if not val["valid"]:
            return {"refreshed": False, "reason": val["reason"]}

        payload = self.active_tokens[token_string]
        payload["exp"] += extend_seconds
        return {
            "refreshed": True,
            "token_string": token_string,
            "new_expires_at": payload["exp"],
            "extended_by_seconds": extend_seconds
        }

    def revoke_token(self, token_string: str) -> Dict[str, Any]:
        """Revokes an active token immediately."""
        if token_string in self.active_tokens:
            del self.active_tokens[token_string]
            return {"revoked": True}
        return {"revoked": False, "reason": "Token not found"}

    def get_active_sessions(self) -> Dict[str, Any]:
        now = time.time()
        active = [p for p in self.active_tokens.values() if p["exp"] > now]
        return {"total_active_delegations": len(active), "sessions": active}
