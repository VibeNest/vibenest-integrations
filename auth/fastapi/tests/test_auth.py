from pathlib import Path

from app.vibenest_auth import AuthSettings, callback_url_from_request


ENV = {
    "VIBENEST_AUTH_ISSUER": "https://vibenest.net/",
    "VIBENEST_AUTH_CLIENT_ID": "client-reference",
    "VIBENEST_AUTH_CLIENT_SECRET": "confidential-placeholder",
    "VIBENEST_AUTH_REDIRECT_URI": "https://reference.example/auth/vibenest/callback",
}


def test_callback_is_pinned_to_configured_uri():
    settings = AuthSettings.from_env(ENV)
    assert callback_url_from_request("?code=abc&state=state", settings) == (
        "https://reference.example/auth/vibenest/callback?code=abc&state=state"
    )


def test_public_and_confidential_clients_are_explicit():
    assert AuthSettings.from_env(ENV).client_secret == "confidential-placeholder"
    assert AuthSettings.from_env({**ENV, "VIBENEST_AUTH_CLIENT_SECRET": ""}).client_secret is None


def test_security_invariants_are_present():
    source = Path("app/vibenest_auth.py").read_text(encoding="utf-8")
    assert '"code_challenge_method": "S256"' in source
    assert 'request.session.pop("vibenest_oidc", None)' in source
    assert "hmac.compare_digest" in source
    assert 'algorithms=["RS256", "ES256"]' in source
    assert "x-forwarded-host" not in source.lower()
    assert '"plain"' not in source
