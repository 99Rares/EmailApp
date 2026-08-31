from email_app.services.rules import identify_and_split, parse_json


def test_identify_and_split_uses_detected_separator():
    assert identify_and_split("one-two") == (["one", "two"], "-")


def test_parse_json_ignores_worker_rules_and_extracts_forwarding_data():
    rules = [
        {"actions": [{"type": "worker"}]},
        {
            "id": "rule-1",
            "name": "Mail@Rule created at 2026-01-01 12:00:00",
            "matchers": [{"field": "to", "value": "alias@example.test"}],
            "actions": [{"type": "forward", "value": ["admin@example.test"]}],
        },
    ]

    assert parse_json(rules) == [
        {
            "id": "rule-1",
            "name": "Mail",
            "creation_time": "01.01.2026 12:00",
            "generated_email": "alias@example.test",
            "destination_email": "admin@example.test",
        }
    ]
