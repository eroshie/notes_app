from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import smtplib
import random
import bcrypt
import os
from email.mime.text import MIMEText

app = Flask(__name__)

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://alvinero:alvinero@msmes.ybbzkya.mongodb.net/?appName=MSMEs")
EMAIL = os.environ.get("EMAIL", "sheshablearaya@gmail.com")
PASSWORD = os.environ.get("EMAIL_PASSWORD", "fqik fjsk cdao kdkc")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "4533f4cc0403ae481bc5c0c529735d163593bcbaee373b6869d70d9529ebe7b1")

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client["MSMEs"]
users_collection = db["users"]
notes_collection = db["notes"]

app.config["JWT_SECRET_KEY"] = JWT_SECRET
jwt = JWTManager(app)

otp_storage = {}

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

@app.route("/")
def home():
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    return send_from_directory(template_dir, "index.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    otp = random.randint(100000, 999999)
    otp_storage[email] = {"otp": otp, "password": hashed_password}
    send_otp(email, otp)
    return jsonify({"message": "OTP sent to your email"}), 200

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    if email not in otp_storage:
        return jsonify({"error": "No OTP request found for this email"}), 400
    if otp_storage[email]["otp"] != int(otp):
        return jsonify({"error": "Invalid OTP"}), 400
    users_collection.insert_one({"email": email, "password": otp_storage[email]["password"]})
    del otp_storage[email]
    return jsonify({"message": "Registration successful"}), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
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
    notes = list(notes_collection.find())
    return jsonify([serialize(note) for note in notes]), 200

@app.route("/notes/<note_id>", methods=["GET"])
@jwt_required()
def get_note(note_id):
    note = notes_collection.find_one({"_id": ObjectId(note_id)})
    if not note:
        return jsonify({"error": "Note not found"}), 404
    return jsonify(serialize(note)), 200

@app.route("/notes", methods=["POST"])
@jwt_required()
def add_note():
    data = request.get_json()
    if not data.get("title") or not data.get("content"):
        return jsonify({"error": "Title and content are required"}), 400
    result = notes_collection.insert_one({"title": data["title"], "content": data["content"]})
    return jsonify({"message": "Note created", "id": str(result.inserted_id)}), 201

@app.route("/notes/<note_id>", methods=["PUT"])
@jwt_required()
def update_note(note_id):
    data = request.get_json()
    notes_collection.update_one(
        {"_id": ObjectId(note_id)},
        {"$set": {"title": data["title"], "content": data["content"]}}
    )
    return jsonify({"message": "Note updated"}), 200

@app.route("/notes/<note_id>", methods=["DELETE"])
@jwt_required()
def delete_note(note_id):
    notes_collection.delete_one({"_id": ObjectId(note_id)})
    return jsonify({"message": "Note deleted"}), 200

if __name__ == "__main__":
    app.run(debug=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)