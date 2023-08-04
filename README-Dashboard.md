# Mal-Parse Analysis Dashboard - User Guide

Prerequisites:
-> Python 3.x
-> Django 4.x

+ Installation Steps:

-> Navigate to the project directory in your terminal (or run mal-parse.py in non-interactive mode, see README.md)

# To set up the necessary database structures, run the following commands in your terminal:

$ python3 manage.py makemigrations

# To apply the database changes you just created, run:

$ python3 manage.py migrate --run-syncdb

# Create a superuser account (required) that you can use to log in to the admin dashboard. Run the following commands and create your own creds (I use malparse : malparse ):

$ python3 manage.py createsuperuser --username malparse --email admin@example.com

# Note: This command will prompt you to provide a password for the superuser account.

# To load the initial data into the application, run:

$ python3 manage.py load_data

# Start the Django development server:

$ python3 manage.py runserver

-> Accessing the Dashboard

# Open your web browser and navigate to 127.0.0.1:8000.

# You will be redirected to the admin login page. Enter the username and password for the superuser account you created during the installation steps.
# After logging in, you will be redirected to the Daily Reports page where you can view the malware threat data.
