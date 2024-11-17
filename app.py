from flask import Flask, render_template, request, flash, redirect, url_for, session
from constants import EMAIL_LIST, USER_CREDENTIALS
from logic import *
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
        generated_email = generate_random_email(generated_email)
        action_type = request.form.get("action_type")

        if generated_email and destination_email:
            success = add_email_routing_rule(generated_email, destination_email, action_type, name)
            return redirect(url_for("index"))


@app.route("/delete-rule/<rule_id>", methods=["POST"])
@login_required
def delete_rule(rule_id):
    success = delete_email_routing_rule(rule_id)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
