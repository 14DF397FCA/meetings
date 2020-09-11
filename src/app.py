import datetime
import time
from datetime import datetime

import jwt
from flask import Flask, request, jsonify, abort, make_response
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.sql import func
from meeting import Meeting

app = Flask(__name__)
app.config["SECRET_KEY"] = "Aanugh8yi2shoh0yooxohngaepheeth0eis8ohbaiyoh7yaitu"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://dev:dev@172.17.0.1/meeting"
app.config["SQLALCHEMY_COMMIT_ON_TEARDOWN"] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = "users"
    user_id: int = db.Column(db.Integer, primary_key=True)
    email: str = db.Column(db.String(32), index=True, unique=True, nullable=False)
    user_name: str = db.Column(db.String(32), nullable=False)
    password: str = db.Column(db.String(128), nullable=False)
    first_name: str = db.Column(db.String(32), nullable=True)
    last_name: str = db.Column(db.String(32), nullable=True)
    activated: bool = db.Column(db.Boolean, default=False)
    enabled: bool = db.Column(db.Boolean, default=True)
    created_at: datetime = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at: datetime = db.Column(db.DateTime(timezone=True), default=func.now())

    def __repr__(self) -> str:
        return repr(self.to_json())

    def to_json(self):
        return {
            "user_id": self.user_id,
            "email": self.email,
            "user_name": self.user_name,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "activated": self.activated,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {"user_id": self.user_id, "exp": time.time() + expires_in},
            app.config["SECRET_KEY"], algorithm="HS256")

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, "app.config['SECRET_KEY']", algorithms=["HS256"])
        except:
            return
        return User.query.get(data["user_id"])


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({"error": "Not found"}), 404)


@app.route("/", methods=["GET"])
@app.route("/index", methods=["GET"])
def index():
    return jsonify({"status": "ok"})


@app.route("/users", methods=["GET"])
def get_user_list():
    users = [user.to_json() for user in User.query.all()]
    return jsonify({"users": users})


@app.route("/users", methods=["POST"])
def user_add():
    user_name = request.json.get("user_name")
    password = request.json.get("password")
    email = request.json.get("email")

    if user_name is None or password is None or email is None:
        abort(400)

    if User.query.filter_by(email=email).first() is not None:
        abort(400)

    user = User(user_name=user_name)
    user.hash_password(password)
    user.email = email
    db.session.add(user)
    db.session.commit()
    return jsonify({"user": user.to_json()}), 201


# by email
@app.route("/users/<string:email>", methods=["GET"])
def user_info(email: str):
    user = User.query.filter_by(email=email).first()
    if user is None:
        abort(404)
    return jsonify({"user": user.to_json()})


# by email
@app.route("/users/<string:email>", methods=["PUT"])
def user_update(email: str):
    user = User.query.filter_by(email=email).first()
    if user is None:
        abort(404)
    if not request.json:
        abort(400)
    user.first_name = request.json.get("first_name", user.first_name)
    user.last_name = request.json.get("last_name", user.last_name)
    user.password = request.json.get("password", user.password)
    user.activated = request.json.get("activated", user.activated)
    user.enabled = request.json.get("enabled", user.enabled)
    user.updated_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({"user": user.to_json()})


@app.route("/meeting", methods=["GET"])
def meeting_list():
    meetings = [meeting.to_json() for meeting in Meeting.query.filter_by(deleted=False).all()]
    return jsonify({"meetings": meetings})


@app.route("/meeting", methods=["POST"])
def meeting_add():
    name = request.json.get("name")

    if name is None:
        abort(400)

    meeting = Meeting(name=name)
    if "members" in request.json:
        meeting.members = request.json.get("members")
    db.session.add(meeting)
    db.session.commit()
    return jsonify({"meeting": meeting.to_json()}), 201


@app.route("/meeting/<int:meeting_id>", methods=["GET"])
def meeting_info(meeting_id: int):
    meeting = Meeting.query.filter_by(meeting_id=meeting_id).first()
    if meeting is None:
        abort(404)
    return jsonify({"meeting": meeting.to_json()})


@app.route("/meeting/<int:meeting_id>", methods=["PUT"])
def meeting_update(meeting_id: int):
    meeting = Meeting.query.filter_by(meeting_id=meeting_id).first()
    if meeting is None:
        abort(404)
    if not request.json:
        abort(400)

    meeting.name = request.json.get("name", meeting.name)
    meeting.description = request.json.get("description", meeting.description)
    meeting.public = request.json.get("public", meeting.public)
    meeting.date_start = request.json.get("date_start", meeting.date_start)
    meeting.date_end = request.json.get("date_end", meeting.date_end)
    meeting.place = request.json.get("place", meeting.place)
    meeting.author_id = request.json.get("author_id", meeting.author_id)
    meeting.owner_id = request.json.get("owner_id", meeting.owner_id)
    meeting.members = request.json.get("members", meeting.members)
    meeting.created_at = request.json.get("created_at", meeting.created_at)
    meeting.updated_at = datetime.datetime.utcnow()
    meeting.completed = request.json.get("completed", meeting.completed)
    return jsonify({"meeting": meeting.to_json()})


@app.route("/meeting/<int:meeting_id>", methods=["DELETE"])
def meeting_delete(meeting_id: int):
    meeting = Meeting.query.filter_by(meeting_id=meeting_id).first()
    meeting.deleted = True
    meeting.updated_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({"meeting": meeting.to_json()})


#   Add authentication of users
#   Add authenticated user as author, owner, and member of meeting
#   Get meetings where user is author
#   Get meetings where user is owner
#   Get meetings where user is member
#   Get meetings where user is author, owner or member and meeting is not completed


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
