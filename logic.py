import os
import re
from zoneinfo import ZoneInfo
from flask import flash, jsonify, redirect, session, url_for
import requests
import datetime

from constants import CLOUDFLARE_API_TOKEN, PLACEHOLDER_EMAIL_DOMAIN, ROUTING_URL


# Function to delete an email routing rule by ID
def delete_email_routing_rule(rule_id):
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    delete_url = f"{ROUTING_URL}/{rule_id}"
    response = requests.delete(delete_url, headers=headers)

    if response.status_code == 200:
        flash("Routing rule deleted successfully!", "success")
        return True
    else:
        flash(
            f"Failed to delete routing rule: {response.json().get('errors', 'Unknown error')}",
            "error",
        )
        print(f"Error: {response.status_code} - {response.json()}")
        return False


# Function to generate a random email address using the Random Word API
def generate_random_email(text=None):
    try:
        # Remove domain if '@' is present
        text = text.split("@")[0] if text else ""
        words = identify_and_split(text) if text else []

        # Fetch additional random words as needed
        missing_words = 3 - len(words)
        if missing_words > 0:
            response = requests.get(
                f"https://random-word-api.vercel.app/api?words={missing_words}&length=5"
            )
            response.raise_for_status()
            words.extend(response.json())

        return f"{'-'.join(words)}@{PLACEHOLDER_EMAIL_DOMAIN}"
    except Exception as e:
        print(f"Error fetching random words: {e}")
        return f"fallback-email@{PLACEHOLDER_EMAIL_DOMAIN}"  # Fallback email


def identify_and_split(text):
    # Use regular expression to find the separator(s)
    separators = re.findall(r"[^a-zA-Z0-9]+", text)
    unique_separators = list(set(separators))

    if len(unique_separators) == 1:
        # If there's a single unique separator, split by it
        return text.split(unique_separators[0])
    elif len(unique_separators) > 1:
        # If there are multiple separators, split by all of them
        pattern = f"[{''.join(map(re.escape, unique_separators))}]+"
        return re.split(pattern, text)
    else:
        # If no separators are found, return the text as a single-element list
        return [text]


# Function to add a new email routing rule
def add_email_routing_rule(generated_email, destination_email, action_type, name):
    # Generate a random destination email if it's empty and the action type is 'forward'

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    name = name if name else "---"

    # Prepare the action based on the selected type
    action = {"type": action_type}

    if action_type == "forward" and destination_email:
        action["value"] = [destination_email]

    romania_time = datetime.datetime.now(ZoneInfo("Europe/Bucharest"))
    data = {
        "matchers": [{"type": "literal", "field": "to", "value": generated_email}],
        "actions": [action],
        "enabled": True,
        "name": f"{name}@Rule created at {romania_time}",
    }

    response = requests.post(ROUTING_URL, headers=headers, json=data)
    if response.status_code == 200:
        flash("Routing rule added successfully!", "success")
        return True
    else:
        flash(
            f"Failed to add routing rule: {response.json().get('errors', 'Unknown error')}",
            "error",
        )
        print(f"Error: {response.status_code} - {response.json()}")
        return False


def get_email_routing_addresses():
    """Fetch the list of email routing addresses from Cloudflare."""
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }
    response = requests.get(ROUTING_URL, headers=headers)
    if response.status_code == 200:
        return parse_json(response.json().get("result", []))
    else:
        print(f"Error: {response.status_code} - {response.json()}")
        return None


def parse_json(rules):
    parsed_rules = []

    # Parse each rule and extract only the relevant details
    for rule in rules:
        # Skip rules with "worker" type actions
        if rule.get("actions")[0].get("type") == "worker":
            continue

        # Extract the name and split it into 'name' and 'creation_time' if possible
        name = rule.get("name", "No+creation+time+available")
        name_and_date = name.split("@") if "@" in name else ["---", name]
        print(name_and_date)
        rule_data = {
            "creation_time": name_and_date[1],
            "name": name_and_date[0],
            "id": rule.get("id", None),
            "generated_email": "",
            "destination_email": "",
        }

        # Strip the prefix "Rule created at " if it exists
        if rule_data["creation_time"].startswith("Rule created at "):
            rule_data["creation_time"] = rule_data["creation_time"][
                len("Rule created at ") :
            ]

        # Get generated email from matchers
        for matcher in rule.get("matchers", []):
            if matcher.get("field") == "to":
                rule_data["generated_email"] = matcher.get("value", "Unknown")

        # Get destination email from actions
        for action in rule.get("actions", []):
            if action.get("type") == "forward":
                rule_data["destination_email"] = action.get("value", ["Unknown"])[0]
            else:
                rule_data["destination_email"] = action.get("value", ["Drop"])[0]

        # Append the rule data to the parsed rules list
        if rule_data["generated_email"] == "":
            continue
        parsed_rules.append(rule_data)

    return parsed_rules


def login_required(f):
    """Decorator to protect routes that require authentication."""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function
