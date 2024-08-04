from flask_restx import fields
from app import api

user_model = api.model('User', {
    'id': fields.Integer(readonly=True),
    'username': fields.String(required=True),
    'first_name': fields.String(required=True),
    'last_name': fields.String(required=True),
    'email': fields.String(required=True),
    'role': fields.String(enum=['User', 'Admin']),
    'created_at': fields.DateTime(readonly=True),
    'updated_at': fields.DateTime(readonly=True),
    'is_active': fields.Boolean()
})

user_update_model = api.model('User', {
    'username': fields.String(required=True),
    'first_name': fields.String(required=True),
    'last_name': fields.String(required=True),
    'email': fields.String(required=True)
})

login_model = api.model('Login', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
})

register_model = api.model('Register', {
    'username': fields.String(required=True),
    'first_name': fields.String(required=True),
    'last_name': fields.String(required=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True)
})


password_reset_request_model = api.model('PasswordResetRequest', {
    'email': fields.String(required=True, description='User email address')
})

password_reset_model = api.model('PasswordReset', {
    'new_password': fields.String(required=True, description='New password')
})


change_password_model = api.model('ChangePassword', {
    'current_password': fields.String(required=True, description='Current password of the user'),
    'new_password': fields.String(required=True, description='New password for the user')
})
