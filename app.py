from flask import Flask, render_template, request, jsonify
import hashlib
import json
import os

app = Flask(__name__)

PASSWORD_FILE = "passwords.json"

# Create file if not exists
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        json.dump([], f)

def check_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check_password():
    password = request.json.get("password")

    if not password:
        return jsonify({"error": "Password required"}), 400

    hashed = hashlib.sha256(password.encode()).hexdigest()

    with open(PASSWORD_FILE, "r") as f:
        stored = json.load(f)

    reused = hashed in stored
    strength = check_strength(password)

    if not reused:
        stored.append(hashed)
        with open(PASSWORD_FILE, "w") as f:
            json.dump(stored, f)

    recommendation = ""
    if strength == "Weak":
        recommendation = "Use at least 8 characters with uppercase, lowercase, numbers & symbols."
    elif reused:
        recommendation = "Avoid reusing passwords across applications."
    else:
        recommendation = "Good password practice!"

    return jsonify({
        "strength": strength,
        "reused": reused,
        "recommendation": recommendation
    })

if __name__ == "__main__":
    app.run(debug=True)
    