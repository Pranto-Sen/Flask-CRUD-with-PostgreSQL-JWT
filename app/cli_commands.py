import click
from flask.cli import with_appcontext
from .models import User, UserRole
from . import db

@click.command('create-admin')
@with_appcontext
def create_admin():
    try:
        # Check if an admin already exists
        admin = User.query.filter_by(role=UserRole.ADMIN).first()
        if admin:
            click.echo('An admin already exists. No additional admins will be created.')
            return

        # Prompt for username and password if no admin exists
        username = click.prompt('Enter the username ')
        password = click.prompt('Enter the password ', hide_input=True, confirmation_prompt=True)

        email = click.prompt('Enter the email ')
        first_name = click.prompt('Enter the First name ')
        last_name = click.prompt('Enter the Last name ')

        # Check if the username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            click.echo('This username already exists. Try another username.')
            return

        # Create new admin user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=UserRole.ADMIN,
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f'Admin user {username} has been created.')
    
    except Exception as e:
        click.echo(f'An error occurred: {e}')

def init_cli_commands(app):
    app.cli.add_command(create_admin)

# To create an admin user, run:
# flask create-admin
