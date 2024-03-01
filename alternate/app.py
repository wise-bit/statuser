from flask import Flask, request, jsonify, render_template
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
import os

app = Flask(__name__)
load_dotenv()

state = {"status": "inactive"}
hashed_password = os.getenv("HASHED_PASSWORD")


@app.route('/')
def index():
    """Serve the index HTML file."""
    return render_template("index.html")


@app.route("/get-state", methods=["GET"])
def get_state():
    """Endpoint to get the current state."""
    return jsonify(state)


@app.route("/change-state", methods=["POST"])
def change_state():
    """Endpoint to change the state. Requires password authentication."""
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({"message": "Authentication required"}), 401

    print(check_password_hash(hashed_password, auth.password))
    print(hashed_password, auth.password)

    if check_password_hash(hashed_password, auth.password):
        state["status"] = "active" if state["status"] == "inactive" else "inactive"  # Toggle
        return jsonify({"message": "State changed successfully", "new_state": state["status"]})
    else:
        return jsonify({"message": "Authentication failed"}), 403


if __name__ == "__main__":
    app.run(debug=True, load_dotenv=True, port=5002)
