import importlib

import bcrypt
import pytest


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("MY_USER", "admin")
    monkeypatch.setenv(
        "ADMIN_PASSWORD_HASH", bcrypt.hashpw(b"correct password", bcrypt.gensalt()).decode()
    )
    monkeypatch.setenv("EMAIL_LIST", "admin@example.test")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    import email_app.config as constants
    import app

    importlib.reload(constants)
    application = importlib.reload(app).app
    application.config.update(TESTING=True, WTF_CSRF_TIME_LIMIT=None)
    return application.test_client()


def csrf_token(client):
    client.get("/login")
    with client.session_transaction() as current_session:
        return current_session["csrf_token"]


def test_login_rejects_missing_csrf_token(client):
    response = client.post("/login", data={"username": "admin", "password": "correct password"})
    assert response.status_code == 400


def test_login_sets_security_headers(client):
    response = client.get("/login")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_add_rule_rejects_unapproved_forwarding_destination(client, monkeypatch):
    import app

    monkeypatch.setattr(app, "generate_random_email", lambda _: "alias@example.test")
    token = csrf_token(client)
    with client.session_transaction() as current_session:
        current_session["user"] = "admin"
    response = client.post(
        "/add-rule",
        data={
            "csrf_token": token,
            "generated_email": "alias",
            "destination_email": "attacker@example.test",
            "app_name": "test",
            "action_type": "forward",
        },
    )
    assert response.status_code == 400


def test_destination_filter_is_applied_server_side(client, monkeypatch):
    import app

    monkeypatch.setattr(
        app,
        "get_email_routing_addresses",
        lambda: [
            {"destination_email": "admin@example.test", "generated_email": "keep@example.test"},
            {"destination_email": "other@example.test", "generated_email": "hide@example.test"},
        ],
    )
    with client.session_transaction() as current_session:
        current_session["user"] = "admin"
    response = client.get("/?destination=admin@example.test")
    assert b"keep@example.test" in response.data
    assert b"hide@example.test" not in response.data


def test_table_rows_expose_editable_rule_data(client, monkeypatch):
    import app

    monkeypatch.setattr(
        app,
        "get_email_routing_addresses",
        lambda: [
            {
                "destination_email": "admin@example.test",
                "generated_email": "edit@example.test",
                "name": "Service",
                "creation_time": "01.01.2026 12:00",
                "id": "rule-1",
            }
        ],
    )
    with client.session_transaction() as current_session:
        current_session["user"] = "admin"
    response = client.get("/")
    assert b'data-generated-email="edit@example.test"' in response.data
    assert b"/static/app.js" in response.data
