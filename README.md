# User Authentication Project
Overview
This project is a user authentication system designed to demonstrate secure and efficient user management. It includes features such as user registration, login, and session management.

# Features
User Registration: Allows new users to create an account.
User Login: Provides a secure login mechanism.
Session Management: Manages user sessions with secure tokens.

# Installation
Clone the repository:
git clone https://github.com/VictorAbhishiek/User-Authentication.git
# Navigate to the project directory:
cd User-Authentication

# Install dependencies: Make sure you have Node.js and npm installed. Then run:
npm start 

# Configuration
Create a .env file in the root directory of the project with the following environment variables:
PORT=your_port_number
DB_CONNECTION_STRING=your_database_connection_string
JWT_SECRET=your_jwt_secret_key
Update the configuration as needed for your local environment.

# Running the Application
Start the development server:
npm start

Access the application: Open your browser and navigate to http://localhost:your_port_number

# Usage
Register a new user:
Send a POST request to /api/register with the user details (e.g., username, password).
Login:
Send a POST request to /api/login with your credentials.
Access protected routes:
Use the JWT token obtained from login in the Authorization header of your requests.

# Testing
Run tests:
npm test


# Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request with your changes.
