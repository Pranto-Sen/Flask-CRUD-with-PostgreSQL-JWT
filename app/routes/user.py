from app.models import User, UserRole
from app.schemas import user_model,user_update_model
from flask import request, jsonify, url_for, current_app
from flask_restx import Resource, Namespace
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from app import db, mail
from app.schemas import login_model, register_model, password_reset_request_model, password_reset_model,change_password_model


serializer = URLSafeTimedSerializer('dummy-secret')
user_ns = Namespace('users', description='User operations')

# Only an admin can view all user data, while a normal user can view only their own data.
@user_ns.route('/admin/users')
class UserList(Resource):
    @user_ns.doc(security='Bearer Auth')
    @jwt_required()
    @user_ns.marshal_list_with(user_model)
    def get(self):
        current_user = User.query.get(get_jwt_identity())
        if not current_user:
            return {'message': 'User not found'}, 404
        if current_user.role == UserRole.ADMIN:
            return User.query.all()
        else:
            return [current_user]  


# A specific user can view their own information, while an admin can view any user's information using the user ID.
@user_ns.route('/user/<int:id>')
class UserResource(Resource):
    @user_ns.doc(security='Bearer Auth')
    @jwt_required()
    @user_ns.marshal_with(user_model)
    def get(self, id):
        current_user = User.query.get(get_jwt_identity())
        user = User.query.get(id)
        if not user:
            user_ns.abort(404, 'User not found')
        if current_user.role != UserRole.ADMIN and current_user.id != id:
            # return {'message': 'Unauthorized Access'}, 403
            user_ns.abort(403, 'Unauthorized to access this user')
        return user

    # A specific user can update their own information, while an admin can update any user's information using the user ID

    @user_ns.doc(security='Bearer Auth')
    @jwt_required()
    @user_ns.expect(user_update_model)
    @user_ns.marshal_with(user_update_model)
    def put(self, id):
        current_user = User.query.get(get_jwt_identity())
        user = User.query.get(id)
        if not user:
            user_ns.abort(404, 'User not found')
        if current_user.id != user.id and (current_user.role != UserRole.ADMIN or user.role == UserRole.ADMIN):
            user_ns.abort(403, 'Unauthorized to edit this user')
        
        data = request.json
        
        if 'username' in data and data['username'] != user.username:
            if User.query.filter_by(username=data['username']).first():
                user_ns.abort(400, 'Username already exists')
            user.username = data['username']
        
        if 'email' in data and data['email'] != user.email:
            if User.query.filter_by(email=data['email']).first():
                user_ns.abort(400, 'Email already exists')
            user.email = data['email']
        
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        
        if current_user.role == UserRole.ADMIN and user.role != UserRole.ADMIN:
            if 'role' in data:
                try:
                    new_role = data['role'].upper()
                    if new_role not in UserRole.__members__:
                        user_ns.abort(400, f'Invalid role. Valid roles are: {", ".join(UserRole.__members__.keys())}')
                    user.role = UserRole[new_role]
                except KeyError:
                    user_ns.abort(400, f'Invalid role. Valid roles are: {", ".join(UserRole.__members__.keys())}')
            if 'is_active' in data:
                user.is_active = data['is_active']
        elif current_user.id != user.id and ('role' in data or 'is_active' in data):
            user_ns.abort(403, 'Cannot change role or active status of other admin accounts')
        
        if 'password' in data:
            user.set_password(data['password'])
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            user_ns.abort(500, f'Error updating user: {str(e)}')
        
        return user

    
    # Only admins can delete users
    @user_ns.doc(security='Bearer Auth')
    @jwt_required()
    def delete(self, id):
        current_user = User.query.get(get_jwt_identity())
        user_to_delete = User.query.get(id)
        if not user_to_delete:
            user_ns.abort(404, 'User not found')
        if current_user.role != UserRole.ADMIN:
            return {'message': 'Unauthorized. Only admins can delete users.'}, 403
        
        if (user_to_delete.role == UserRole.ADMIN) and (user_to_delete.id != current_user.id):
            return {'message': 'Unauthorized. Cannot delete admin accounts.'}, 403
        
        if current_user.id == id:
            admin_count = User.query.filter_by(role=UserRole.ADMIN).count()
            if admin_count == 1:
                return {'message': 'Cannot delete the last admin account.'}, 400
        
        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            return {'message': 'User deleted successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'Error deleting user: {str(e)}'}, 500
        

@user_ns.route('/admin/<int:id>/make-admin')
class MakeAdminResource(Resource):
    @user_ns.doc(security='Bearer Auth')
    @jwt_required()
    def post(self, id):
        current_user = User.query.get(get_jwt_identity())
        if not current_user or current_user.role != UserRole.ADMIN:
            return {'message': 'Admin access required'}, 403
        
        user = User.query.get(id)
        if not user:
            user_ns.abort(404, 'User not found')
        if user.role == UserRole.ADMIN:
            user_ns.abort(404, 'User is already an Admin')
        user.role = UserRole.ADMIN
        db.session.commit()
        return {'message': f'User {user.username} has been made an admin'}, 200


@user_ns.route('/auth/register')
class Register(Resource):
    @user_ns.expect(register_model)
    def post(self):
        data = request.json
        if User.query.filter_by(username=data['username']).first():
            return {'message': 'Username already exists'}, 400
        if User.query.filter_by(email=data['email']).first():
            return {'message': 'Email already exists'}, 400
        
        new_user = User(
            username=data['username'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            is_active=True
        )
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'Register Successfully'}, 201


@user_ns.route('/auth/login')
class Login(Resource):
    @user_ns.expect(login_model)
    def post(self):
        data = request.json
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        return {'message': 'Invalid credentials'}, 401


@user_ns.route('/auth/forgot-password')
class ForgotPassword(Resource):
    @user_ns.expect(password_reset_request_model)
    def post(self):
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            return {'message': 'Please provide the correct email'}, 200
        token = serializer.dumps(user.email, salt='password-reset-salt')
        
        reset_url = url_for('users_reset_password', token=token, _external=True)
        
        # When using an actual email address and the token is sent to the email address, ensure the following code is uncommented and the mail configuration is correctly set in the .env file.
        
        # msg = Message('Password Reset Request',
        #               sender='noreply@yourdomain.com',
        #               recipients=[user.email])
        # msg.body = f'To reset your password, visit the following link: {reset_url} OR Paste the token "/reset-password/<token>" route {token}'
        # mail.send(msg)
        
        # return {'token': 'If a user with this email exists, a password reset link has been sent.'}, 200

        return {'token': token}, 200


@user_ns.route('/auth/reset-password/<string:token>')
class ResetPassword(Resource):
    @user_ns.expect(password_reset_model)
    def post(self, token):
        try:
            email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        except SignatureExpired:
            return {'message': 'The password reset link has expired.'}, 400
        except BadSignature:
            return {'message': 'The password reset link is invalid.'}, 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return {'message': 'User not found.'}, 404
        
        new_password = request.json.get('new_password')
        user.set_password(new_password)
        db.session.commit()
        
        return {'message': 'Password reset successful'}, 200
    

@user_ns.route('/auth/change-password')
class ChangePassword(Resource):
    @jwt_required()
    @user_ns.expect(change_password_model)
    def post(self):
        data = request.json
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)
        
        if not user.check_password(data['current_password']):
            return {'message': 'Current password is incorrect'}, 400
        
        user.set_password(data['new_password'])  
        db.session.commit()
        
        return {'message': 'Password changed successfully'}, 200


