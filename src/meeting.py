import datetime
from typing import List

from app import db


class Meeting(db.Model):
    __tablename__ = "meetings"
    meeting_id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(32), index=True, nullable=False)
    description: str = db.Column(db.Text)
    public: bool = db.Column(db.Boolean, default=False)
    date_start: datetime = db.Column(db.DateTime(timezone=True))
    date_end: datetime = db.Column(db.DateTime(timezone=True))
    place: str = db.Column(db.String(32))
    author_id: int = db.Column(db.Integer)
    owner_id: int = db.Column(db.Integer)
    members: List[int] = db.Column(db.ARRAY(db.Integer))
    created_at: datetime = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at: datetime = db.Column(db.DateTime(timezone=True), default=func.now())
    completed: bool = db.Column(db.Boolean, default=False)
    deleted: bool = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return repr(self.to_json())

    def to_json(self):
        return {
            "meeting_id": self.meeting_id,
            "name": self.name,
            "description": self.description,
            "public": self.public,
            "date_start": self.date_start,
            "date_end": self.date_end,
            "place": self.place,
            "author_id": self.author_id,
            "owner_id": self.owner_id,
            "members": self.members,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed": self.completed,
            "deleted": self.deleted
        }
