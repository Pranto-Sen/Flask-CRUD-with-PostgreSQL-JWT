from app import db, bcrypt
from datetime import datetime
from enum import Enum
from sqlalchemy import func
from datetime import datetime

class UserRole(Enum):
    ADMIN = 'Admin'
    USER = 'User'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):  
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8') 

    def check_password(self, password): 
        return bcrypt.check_password_hash(self.password_hash, password) 

