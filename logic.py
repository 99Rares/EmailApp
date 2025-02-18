import re
import logging
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from flask import flash, redirect, session, url_for
import requests
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
import datetime

from constants import (
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_ZONE_ID,
    PLACEHOLDER_EMAIL_DOMAIN,
    ROUTING_URL,
)


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
        logging.error(f"Error: {response.status_code} - {response.json()}")
        return False


# Function to generate a random email address using the Random Word API
def generate_random_email(text=None):
    try:
        # Remove domain if '@' is present
        text = text.split("@")[0] if text else ""
        words, separator = (identify_and_split(text) if text else ([], '-'))

        # Fetch additional random words as needed
        missing_words = 3 - len(words)
        if missing_words > 0 and separator != ".":
            response = requests.get(
                f"https://random-word-api.vercel.app/api?words={missing_words}&length=5"
            )
            response.raise_for_status()
            words.extend(response.json())

        return f"{separator.join(words)}@{PLACEHOLDER_EMAIL_DOMAIN}"
    except Exception as e:
        logging.error(f"Error fetching random words: {e}")
        return f"fallback-email@{PLACEHOLDER_EMAIL_DOMAIN}"  # Fallback email


def identify_and_split(text):
    if not text:
        return [], "-"

    # Use regular expression to find the separator(s)
    separators = re.findall(r"[^a-zA-Z0-9]+", text)
    unique_separators = list(set(separators))

    if len(unique_separators) == 1:
        # If there's a single unique separator, split by it
        return text.split(unique_separators[0]), unique_separators[0]
    elif len(unique_separators) > 1:
        # If there are multiple separators, split by all of them
        pattern = "|".join(map(re.escape, unique_separators))
        return re.split(pattern, text), unique_separators[0]
    else:
        # If no separators are found, return the text as a single-element list
        return [text], "-"



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

    data = {
        "matchers": [{"type": "literal", "field": "to", "value": generated_email}],
        "actions": [action],
        "enabled": True,
        "name": name,
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
        logging.error(f"Error: {response.status_code} - {response.json()}")
        return False


def get_email_routing_addresses():
    ROUTING_URL_GET = "https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules"
    """Fetch the list of all email routing rules from Cloudflare, handling pagination."""
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }
    page = 1
    all_results = []
    per_page = 50

    while True:
        response = requests.get(
            f"{ROUTING_URL_GET.format(zone_id=CLOUDFLARE_ZONE_ID)}?page={page}&per_page={per_page}",
            headers=headers,
        )
        if response.status_code == 200:
            data = response.json()
            results = data.get("result", [])
            all_results.extend(results)

            # Use total_count and per_page to calculate the total number of pages
            result_info = data.get("result_info", {})
            total_count = result_info.get("total_count", 0)
            if page * per_page >= total_count:
                break

            page += 1
        else:
            logging.error(f"Error: {response.status_code} - {response.json()}")
            break

    return parse_json(all_results)


def get_json(data):
    """Parse the JSON result (example function, replace with actual implementation)."""
    # Example: Return the data directly or process it as needed
    return data


def get_email_routing_rule(rule_id):
    """
    Fetch the list of email routing addresses from Cloudflare by rule ID.
    :param rule_id: ID of the email routing rule.
    :return: Parsed email routing rule or None if an error occurs.
    """
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }
    get_url = f"{ROUTING_URL}/{rule_id}"

    try:
        response = requests.get(get_url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.info(f"Response received: {response.json()}")
        result = response.json().get("result", {})
        return get_json(result)
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP Request failed: {e}")
    except KeyError as e:
        logging.error(f"Missing expected key in response: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    return None


def update_rule(email_data):
    """
    Update an email routing rule via Cloudflare API.
    :param email_data: Dictionary containing the updated rule data.
    :return: True if the update is successful, False otherwise.
    """
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    rule_id = email_data.get("id")
    if not rule_id:
        logging.error("Invalid email data: 'id' field is missing.")
        return False

    update_url = f"{ROUTING_URL}/{rule_id}"

    # Remove the "value" field from "drop" actions
    if "actions" in email_data:
        for action in email_data["actions"]:
            if action.get("type") == "drop":
                action.pop("value", None)

    allowed_fields = {"actions", "matchers", "enabled", "name"}
    filtered_data = {
        key: email_data[key] for key in allowed_fields if key in email_data
    }

    logging.info(f"Payload to be sent: {filtered_data}")
    logging.info(f"Request URL: {update_url}")

    try:
        response = requests.put(update_url, headers=headers, json=filtered_data)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.info(f"Rule updated successfully: {response.json()}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to update the rule: {e}")
        if response is not None and response.text:
            logging.error(f"Response content: {response.text}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def get_rule_id_by_generated_email(generated_email):
    """
    Retrieves the rule ID for a given generated email.
    :param generated_email: The generated email address to search for.
    :return: The rule ID if found, otherwise None.
    """
    rules = get_email_routing_addresses()  # Replace with your function to fetch rules
    for rule in rules:
        if rule.get("generated_email") == generated_email:
            return rule.get("id")
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
        logging.info(f"Name and date: {name_and_date}")
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


def handle_destination_email(destination_email, action_type):
    if not destination_email or action_type == "drop":
        return "Drop"
    return destination_email


def append_timestamp_to_name(name):
    try:
        romania_time = datetime.datetime.now(ZoneInfo("Europe/Bucharest"))
    except ZoneInfoNotFoundError:
        logging.error(
            "ZoneInfo key 'Europe/Bucharest' not found. Using UTC time instead."
        )
        romania_time = datetime.datetime.now(datetime.timezone.utc)
    return f"{name}@Rule created at {romania_time}"


def process_rule(rule_id, generated_email, destination_email, action_type, name):
    if not rule_id:
        return add_email_routing_rule(
            generated_email, destination_email, action_type, name
        )
    else:
        email_data = {
            "id": rule_id,
            "actions": [{"type": action_type}],
            "matchers": [
                {
                    "field": "to",
                    "type": "literal",
                    "value": generated_email,
                }
            ],
            "enabled": True,
            "name": name,
        }

        if action_type != "drop":
            email_data["actions"][0]["value"] = [destination_email]

        return update_rule(email_data)
