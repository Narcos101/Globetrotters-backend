from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

import uuid
import json
import os
import random

app = Flask(__name__)
CORS(app)

TOKEN_ETIME = 6 * 60

# SQLite Database Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///game_db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "3ed0b782b00d803b16b17bdcb312a943ba7a4d5d5a896751fc933321c2e0ce31"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=TOKEN_ETIME)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

SCORE_TO_BE_ADDED = 10

class GameSession(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rounds_data = db.Column(db.Text, nullable=False, default='{}')  # Store JSON as text
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    correct_questions = db.Column(db.Integer, nullable=False, default=0)
    incorrect_questions = db.Column(db.Integer, nullable=False, default=0)

    def get_rounds_data(self):
        return json.loads(self.rounds_data) if self.rounds_data else {}
    
    def set_rounds_data(self, data):
        self.rounds_data = json.dumps(data)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

with app.app_context():
    db.create_all()

def load_json():
    if not os.path.exists('countries.json'):
        return None, "Error: JSON file not found."
    try:
        with open('countries.json', "r", encoding="utf-8") as file:
            data = json.load(file)
            return data, None 
    except json.JSONDecodeError:
        return None, "Error: Invalid JSON format in file."
    except Exception as e:
        return None, f"Unexpected Error: {str(e)}"

@app.route('/start_session', methods=['POST'])
@jwt_required()
def start_session():
    user_id = get_jwt_identity()
    session = GameSession(user_id=user_id)
    db.session.add(session)
    db.session.commit()
    return jsonify({"message": "Game session started", "session_id": session.id}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({"message": "Login successful", "token": access_token})
    elif not user:
        return jsonify({"error": "User not registered"}), 401
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data["username"]
    password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

def get_available_countries(used_questions):
    countries, error = load_json()
    while True:
        random_idx = random.randint(0, len(countries)-1)
        if random_idx not in used_questions:
            break
    random_country = countries[random_idx]
    random_options = random.sample(countries, 6)
    random_options = [d['name'] for d in random_options if d['name'] != random_country['name']][:5]
    return random_country, random_idx, random_options

@app.route('/api/get_round', methods=["GET", "POST"])
@jwt_required()
def get_round():
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    session = GameSession.query.filter_by(id=session_id, end_time=None).first()
    if not session:
        return jsonify({"error": "No active game session found for this session_id"}), 404
    rounds_data = session.get_rounds_data()
    used_questions = set(map(int, rounds_data.keys()))
    random_country, random_country_idx, random_options = get_available_countries(used_questions)
    clues = random_country['clues']
    options = [random_country['name']] + random_options
    random.shuffle(options)
    new_round = {"isCorrect": False, "selectedOption": -1, "correctOption": random_country['name'],
                "additional_details": random_country['funFacts']}
    rounds_data[random_country_idx] = new_round
    session.set_rounds_data(rounds_data)
    db.session.commit()
    return {'uuid': random_country_idx, "roundno": len(rounds_data), 'answer_destination': clues, 'hint_destinations': options}

@app.route('/api/get_user_info', methods=["GET"])
@jwt_required()
def get_user_details():
    user_data = {}
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    sessions = GameSession.query.filter_by(user_id=user_id).all()
    user_data['username'] = user.username
    if sessions:
        total_correct_cnt = sum(session.correct_questions for session in sessions)
        user_data['total_games_played'] = len(sessions)
        user_data['total_correct_questions'] = total_correct_cnt
    return jsonify(user_data), 200

@app.route('/api/set_round', methods=["POST"])
@jwt_required()
def set_round():
    data = request.get_json()
    session_id = data.get("session_id")
    uuid = str(data.get("uuid"))
    selected_option = str(data.get("selected_option"))

    if not session_id or uuid is None or selected_option is None:
        return jsonify({"error": "session_id, uuid, and selected_option are required"}), 400

    session = GameSession.query.filter_by(id=session_id, end_time=None).first()
    if not session:
        return jsonify({"error": "No active game session found for this session_id"}), 404

    rounds_data = session.get_rounds_data()  # Properly load JSON from text column

    if uuid not in rounds_data:
        return jsonify({"error": "Invalid uuid"}), 400

    is_correct = selected_option == rounds_data[uuid]["correctOption"]

    if is_correct:
        session.correct_questions += 1
    else:
        session.incorrect_questions += 1

    rounds_data[uuid]["selectedOption"] = selected_option
    rounds_data[uuid]["isCorrect"] = is_correct

    session.set_rounds_data(rounds_data)  # Convert dict to JSON and store
    db.session.commit()

    return jsonify({
        "message": "Round updated successfully",
        "updated_round": rounds_data[uuid],
        "isCorrect": is_correct,
        "additional_details": rounds_data[uuid].get('additional_details', ''),
        "correct_questions": session.correct_questions,
        "incorrect_questions": session.incorrect_questions
    }), 200
