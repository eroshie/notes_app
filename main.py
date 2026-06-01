from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import smtplib
import random
import bcrypt
import os
import re
import time
from email.mime.text import MIMEText
from datetime import timedelta

app = Flask(__name__)
CORS(app)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://alvinero:alvinero@msmes.ybbzkya.mongodb.net/?appName=MSMEs")
EMAIL = os.environ.get("EMAIL", "sheshablearaya@gmail.com")
PASSWORD = os.environ.get("EMAIL_PASSWORD", "fqik fjsk cdao kdkc")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "4533f4cc0403ae481bc5c0c529735d163593bcbaee373b6869d70d9529ebe7b1")

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client["MSMEs"]
users_collection = db["users"]
notes_collection = db["notes"]

app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

otp_storage = {}

# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def sanitize(data):
    if isinstance(data, dict):
        return {k: sanitize(v) for k, v in data.items() if not k.startswith("$")}
    return data

def send_otp(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Your OTP Code"
    msg["From"] = EMAIL
    msg["To"] = email
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, email, msg.as_string())

def serialize(note):
    note["_id"] = str(note["_id"])
    return note

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route("/")
def home():
    with open(os.path.join(os.path.dirname(__file__), "templates", "index.html"), "r") as f:
        return f.read()

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = sanitize(request.get_json())
    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid input"}), 400
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    otp = random.randint(100000, 999999)
    otp_storage[email] = {
        "otp": otp,
        "password": hashed_password,
        "expires": time.time() + 300  # 5 minutes
    }
    send_otp(email, otp)
    return jsonify({"message": "OTP sent to your email"}), 200


@app.route("/verify-otp", methods=["POST"])
@limiter.limit("5 per minute")
def verify_otp():
    data = sanitize(request.get_json())
    email = data.get("email")
    otp = data.get("otp")

    if not isinstance(email, str):
        return jsonify({"error": "Invalid input"}), 400
    if email not in otp_storage:
        return jsonify({"error": "No OTP request found for this email"}), 400
    if time.time() > otp_storage[email]["expires"]:
        del otp_storage[email]
        return jsonify({"error": "OTP expired. Please register again."}), 400
    if otp_storage[email]["otp"] != int(otp):
        return jsonify({"error": "Invalid OTP"}), 400

    users_collection.insert_one({"email": email, "password": otp_storage[email]["password"]})
    del otp_storage[email]
    return jsonify({"message": "Registration successful"}), 200


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = sanitize(request.get_json())
    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid input"}), 400
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid email or password"}), 400
    if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"error": "Invalid email or password"}), 400

    token = create_access_token(identity=email)
    return jsonify({"message": "Login successful", "token": token}), 200


@app.route("/notes", methods=["GET"])
@jwt_required()
def get_notes():
    email = get_jwt_identity()
    notes = list(notes_collection.find({"email": email}))
    return jsonify([serialize(note) for note in notes]), 200


@app.route("/notes/<note_id>", methods=["GET"])
@jwt_required()
def get_note(note_id):
    email = get_jwt_identity()
    note = notes_collection.find_one({"_id": ObjectId(note_id), "email": email})
    if not note:
        return jsonify({"error": "Note not found"}), 404
    return jsonify(serialize(note)), 200


@app.route("/notes", methods=["POST"])
@jwt_required()
def add_note():
    email = get_jwt_identity()
    data = sanitize(request.get_json())
    if not data.get("title") or not data.get("content"):
        return jsonify({"error": "Title and content are required"}), 400
    if not isinstance(data["title"], str) or not isinstance(data["content"], str):
        return jsonify({"error": "Invalid input"}), 400
    result = notes_collection.insert_one({
        "email": email,
        "title": data["title"],
        "content": data["content"]
    })
    return jsonify({"message": "Note created", "id": str(result.inserted_id)}), 201


@app.route("/notes/<note_id>", methods=["PUT"])
@jwt_required()
def update_note(note_id):
    email = get_jwt_identity()
    data = sanitize(request.get_json())
    if not isinstance(data.get("title"), str) or not isinstance(data.get("content"), str):
        return jsonify({"error": "Invalid input"}), 400
    notes_collection.update_one(
        {"_id": ObjectId(note_id), "email": email},
        {"$set": {"title": data["title"], "content": data["content"]}}
    )
    return jsonify({"message": "Note updated"}), 200


@app.route("/notes/<note_id>", methods=["DELETE"])
@jwt_required()
def delete_note(note_id):
    email = get_jwt_identity()
    notes_collection.delete_one({"_id": ObjectId(note_id), "email": email})
    return jsonify({"message": "Note deleted"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)