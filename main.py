import bcrypt

# Mock database for storing user credentials
users_db = {}

# Function to register a user
def register(username, password):
    if username in users_db:
        return "Username already exists."
    
    # Hash the password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_db[username] = hashed_pw
    return "User registered successfully."

# Function to authenticate a user
def login(username, password):
    if username not in users_db:
        return "Username not found."
    
    hashed_pw = users_db[username]
    
    # Check if the provided password matches the stored hashed password
    if bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
        return "Login successful."
    else:
        return "Invalid password."

# Example usage
if __name__ == "__main__":
    # Register a new user
    print(register("john_doe", "securepassword123"))
    
    # Attempt to log in
    print(login("john_doe", "securepassword123"))  # Correct password
    print(login("john_doe", "wrongpassword"))      # Incorrect password
