from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import smtplib
import random
import bcrypt
from email.mime.text import MIMEText
from flask import send_from_directory
app = Flask(__name__)


uri = "mongodb+srv://alvinero:alvinero@msmes.ybbzkya.mongodb.net/?appName=MSMEs"
client = MongoClient(uri, server_api=ServerApi('1'))
db = client["MSMEs"]
users_collection = db["users"]
notes_collection = db["notes"]

EMAIL = "sheshablearaya@gmail.com"
PASSWORD = "fqik fjsk cdao kdkc"

otp_storage = {}

app.config["JWT_SECRET_KEY"] = "4533f4cc0403ae481bc5c0c529735d163593bcbaee373b6869d70d9529ebe7b1" 
jwt = JWTManager(app)

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
    return send_from_directory("templates", "index.html")

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


# @app.route("/show_user", methods=["GET"])
# def show_user():
#     data = request.get_json()
#     email = data.get("email")
#     user = users_collection.find_one({"email": email})
#     if not user:
#         return jsonify({"error": "User not found"}), 404
#     return jsonify({"email": user["email"]}), 200

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