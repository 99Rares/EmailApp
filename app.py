from flask import Flask, jsonify, render_template, request, flash, redirect, url_for, session
from constants import EMAIL_LIST, USER_CREDENTIALS
from logic import (
    handle_destination_email,
    generate_random_email,
    append_timestamp_to_name,
    get_rule_id_by_generated_email,
    process_rule,
    get_email_routing_addresses,
    delete_email_routing_rule,
    get_email_routing_rule,
    update_rule,
    login_required
)
import os
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")


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
    return None


@app.route("/api/emails", methods=["GET"])
def get_emails():
    # Get the emails list from the environment variable
    emails_list = EMAIL_LIST
    # Convert the comma-separated string to a list of dictionaries
    emails = [
        {"value": email, "label": email} for email in emails_list.split(",") if email
    ]

    return jsonify(emails)


@app.route("/")
@login_required
def index():
    """Render the index page with the list of email addresses."""
    email_addresses = get_email_routing_addresses()
    email_addresses.sort(
        key=lambda rule: (
            rule["destination_email"] == "Drop",
            rule["destination_email"],
        )
    )
    if email_addresses is None:
        flash("Failed to fetch email routing addresses.", "error")
    return render_template("index.html", email_addresses=email_addresses)


@app.route("/add-rule", methods=["GET", "POST"])
@login_required
def add_rule():
    if request.method == "POST":
        generated_email = request.form.get("generated_email")
        destination_email = request.form.get("destination_email")
        name = request.form.get("app_name")
        action_type = request.form.get("action_type")

        destination_email = handle_destination_email(destination_email, action_type)
        generated_email = generate_random_email(generated_email)
        name = append_timestamp_to_name(name)

        if generated_email and destination_email:
            rule_id = get_rule_id_by_generated_email(generated_email)
            success = process_rule(
                rule_id, generated_email, destination_email, action_type, name
            )

            if success:
                flash("Rule added or updated successfully.", "success")
            else:
                flash("Failed to add or update the rule.", "danger")

        return redirect(url_for("index"))
    return None


@app.route("/delete-rule/<rule_id>", methods=["POST"])
@login_required
def delete_rule(rule_id):
    success = delete_email_routing_rule(rule_id)
    return redirect(url_for("index"))


@app.route("/drop-rule/<rule_id>", methods=["GET", "POST"])
@login_required
def drop_rule(rule_id):
    """
    Drops an email routing rule by updating its action type to 'drop'.
    :param rule_id: The ID of the rule to drop.
    :return: Redirects to the index page.
    """
    email_data = get_email_routing_rule(rule_id)

    if not email_data:
        # Handle case where the rule could not be fetched
        flash("Failed to retrieve the email routing rule.", "error")
        return redirect(url_for("index"))

    # Update the action type to 'drop'
    if "actions" in email_data:
        for action in email_data["actions"]:
            action["type"] = "drop"
    else:
        flash("Invalid rule data structure: 'actions' missing.", "error")
        return redirect(url_for("index"))

    # Attempt to update the rule
    success = update_rule(email_data)

    if success:
        flash("Rule updated successfully to drop.", "success")
    else:
        flash("Failed to update the rule.", "error")

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
