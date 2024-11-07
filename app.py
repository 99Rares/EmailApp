from flask import Flask, render_template, request, flash, redirect, url_for, session
import requests
import datetime
import os
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

# Cloudflare API configuration
ACCOUNT_ID = os.environ.get("ACCOUNT_ID")
CLOUDFLARE_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID")
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")
PLACEHOLDER_EMAIL_DOMAIN = os.environ.get("PLACEHOLDER_EMAIL_DOMAIN")
DESTINATION_EMAIL = os.environ.get("DESTINATION_EMAIL")
MY_USER = os.environ.get("MY_USER")


ROUTING_URL = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/email/routing/rules"


# Read user credentials from environment variables
USER_CREDENTIALS = {
    MY_USER: os.environ.get(
        "ADMIN_PASSWORD_HASH"
    )  # Set the encrypted password hash as an environment variable
}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode("utf-8")

        if username in USER_CREDENTIALS:
            stored_password_hash = USER_CREDENTIALS[username].encode("utf-8")
            if bcrypt.checkpw(password, stored_password_hash):
                session["user"] = username
                flash("Login successful!", "success")
                return redirect(url_for("index"))
            else:
                flash("Invalid username or password", "danger")
        else:
            flash("Invalid username or password", "danger")

        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    if request.method == "POST":
        session.pop("user", None)
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))


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
def generate_random_email():
    try:
        response = requests.get(
            "https://random-word-api.herokuapp.com/word?number=3&length=5"
        )
        response.raise_for_status()  # Raise an error for bad status codes
        words = response.json()
        if len(words) == 3:
            return f"{'-'.join(words)}@{PLACEHOLDER_EMAIL_DOMAIN}"
        else:
            raise ValueError("Received fewer than 3 words from the API")
    except (requests.RequestException, ValueError) as e:
        print(f"Error fetching random words: {e}")
        return f"fallback-email@{PLACEHOLDER_EMAIL_DOMAIN}"  # Fallback email in case of an error


# Function to add a new email routing rule
def add_email_routing_rule(generated_email, destination_email, action_type):
    # Generate a random destination email if it's empty and the action type is 'forward'

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    # Prepare the action based on the selected type
    action = {"type": action_type}

    if action_type == "forward" and destination_email:
        action["value"] = [destination_email]

    data = {
        "matchers": [{"type": "literal", "field": "to", "value": generated_email}],
        "actions": [action],
        "enabled": True,
        "name": f"Rule created at {datetime.datetime.now()}",
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
        if rule.get("actions")[0].get("type") == "worker":
            continue

        rule_data = {
            "creation_time": rule.get(
                "name", "No creation time available"
            ),  # Default if 'name' is missing
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
                rule_data["destination_email"] = action.get("value", ["Unknown"])[
                    0
                ]  # Default if no destination email
            else:
                rule_data["destination_email"] = action.get("value", ["Drop"])[
                    0
                ]  # Default if no destination email

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


@app.route("/")
@login_required
def index():
    """Render the index page with the list of email addresses."""
    email_addresses = get_email_routing_addresses()
    if email_addresses is None:
        flash("Failed to fetch email routing addresses.", "error")
    return render_template("index.html", email_addresses=email_addresses)


@app.route("/add-rule", methods=["GET", "POST"])
def add_rule():
    if request.method == "POST":
        generated_email = request.form.get("generated_email")
        destination_email = request.form.get("destination_email")
        if not generated_email:
            generated_email = generate_random_email()
        else:
            generated_email += f"@{PLACEHOLDER_EMAIL_DOMAIN}"
        if not destination_email:
            destination_email = DESTINATION_EMAIL
        action_type = request.form.get("action_type")

        if generated_email and destination_email:
            success = add_email_routing_rule(
                generated_email, destination_email, action_type
            )
            return redirect(url_for("index"))


@app.route("/delete-rule/<rule_id>", methods=["POST"])
def delete_rule(rule_id):
    success = delete_email_routing_rule(rule_id)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
