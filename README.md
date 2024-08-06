# User Management API

This project is a user management API built with Flask. It includes authentication and authorization using JWT, password encryption with Bcrypt, and email functionality with Flask-Mail.

## Features
- User registration and login
- Password reset via email
- JWT-based authentication
- Role-based access control
- CRUD operations for user management

## Technologies Used
- Flask
- SQLAlchemy
- Flask-Migrate
- Flask-JWT-Extended
- Flask-Bcrypt
- Flask-Mail
- Flask-RESTX
- PostgreSQL
- Python-dotenv

## Getting Started

### Prerequisites
- Python 3.8+
- PostgreSQL

### Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/Pranto-Sen/Flask-CRUD-with-PostgreSQL-JWT.git
    cd Flask-CRUD-with-PostgreSQL-JWT
    ```

2. **Create a virtual environment:**
    ```bash
    python -m venv .venv
    ```

    - On Windows, activate the virtual environment:
      ```bash
      .venv\Scripts\activate
      ```

    - On Linux/Mac, activate the virtual environment:
      ```bash
      source .venv/bin/activate
      ```


3. **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**
    Create a `.env` file in the root directory of the project and add the following variables:
    ```env
    SECRET_KEY=your_secret_key
    DATABASE_URL=your_database_url
    JWT_SECRET_KEY=your_jwt_secret_key
    ```

    This section is for the basic configuration of the application.

    ```env
    MAIL_SERVER=your_mail_server
    MAIL_PORT=your_mail_port
    MAIL_USERNAME=your_mail_username
    MAIL_PASSWORD=your_mail_password
    MAIL_USE_TLS=True or False
    MAIL_USE_SSL=True or False
    ```

    This section is for the password reset functionality. It includes a token verification system that sends a token to the user's email. For testing purposes, a dummy email option is available, which returns the token in the response body instead of sending an email. When you use the actual email, the token will be sent to the provided email address. Adjust the configuration accordingly based on whether you're using the dummy email for testing or the actual email for real scenarios.


## Database Migrations

To manage database migrations, use Flask-Migrate commands:

- **Initialize migrations:**
    ```bash
    flask db init
    ```

- **Generate a new migration:**
    ```bash
    flask db migrate -m "Initial migration."
    ```

- **Apply migrations:**
    ```bash
    flask db upgrade
    ```
 ## CLI Commands

- **Create an admin user when first time assign as an admin**
    ```bash
    flask create-admin
    ```
    - After running this command in the command line, you will be prompted to provide information such as username, password, email, first name, and last name.


- **Run the application:**
    ```bash
    flask run
    ```

## API Endpoints

- **POST `/api/auth/register`**
    - Register a new user
    - Request body:
      
      ```json
      {
          "username": "john",
          "first_name": "John",
          "last_name": "Doe",
          "email": "john@example.com",
          "password": "1234"
      }
      ```
    - **Response:**
      
      ```json
      {
          "message": "Register Successfully"
      }
      ```
      
- **POST `/api/auth/login`**
    - Log in a user
    - **Request Body:**
      
      ```json
      {
          "username": "john",
          "password": "1234"
      }
      ```
    - **Response:**
      
      After successfully logging in, you will receive an access token. To use this token, enter it in the authorization box, keeping the `Bearer` keyword followed by the access token, for example: `Bearer <access_token>`.


- **GET `/api/admin/users`**
    - Get all users (Only an admin can retrieve all users.)


- **GET `/api/users/<id>`**
    - Get user by ID ( A user can retrieve only their own profile, while an admin can retrieve any user's profile by user ID.)


- **PUT `/api/users/<id>`**
    - Update user by ID (A user can update only their own profile, while an admin can update any user's profile except another admin's profile)
    - Request body:
      
      ```json
      {
          "username": "newusername",
          "first_name": "NewFirstName",
          "last_name": "NewLastName",
          "email": "newemail@example.com"
      }
      ```


- **DELETE `/api/users/<id>`**
    - Delete user by ID (An admin can delete their own account and other user accounts, but not the accounts of other admins.)


- **POST `/api/auth/password-reset-request`**
    - Request a password reset
    - Request body:
      
      ```json
      {
          "email": "john@example.com"
      }
      ```
  - **Response:**
    
      If the email is valid for a registered user, a token will be generated. Use this token to set a new password..


- **POST `/api/auth/reset-password/{token}`**
    - put the token 
    - Reset the password
    - Request body:
      
      ```json
      {
          "new_password": "newpassword"
      }
      ```


- **POST `/api/auth/change-password`**
    - Change the password
    - Request body:
      
      ```json
      {
          "current_password": "currentpassword",
          "new_password": "newpassword"
      }
      ```









