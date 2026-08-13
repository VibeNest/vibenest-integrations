from pathlib import Path


def test_combined_app_uses_the_auth_session_subject_for_payments():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert 'request.session.get("user")' in source
    assert 'user.get("subject")' in source
    assert "buyerKey" not in source
    assert "create_auth_router" in source
    assert "create_payment_router" in source
