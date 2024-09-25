import tkinter as tk
from tkinter import messagebox
import bcrypt

# Mock database for storing user credentials
users_db = {}

# Function to register a user
def register_user():
    username = entry_username.get()
    password = entry_password.get()
    
    if username in users_db:
        messagebox.showerror("Error", "Username already exists.")
        return
    
    # Hash the password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_db[username] = hashed_pw
    messagebox.showinfo("Success", "User registered successfully.")

# Function to authenticate a user
def login_user():
    username = entry_username.get()
    password = entry_password.get()
    
    if username not in users_db:
        messagebox.showerror("Error", "Username not found.")
        return
    
    hashed_pw = users_db[username]
    
    # Check if the provided password matches the stored hashed password
    if bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
        messagebox.showinfo("Success", "Login successful.")
    else:
        messagebox.showerror("Error", "Invalid password.")

# Create the main application window
app = tk.Tk()
app.title("Simple Auth System")

# Username label and entry
label_username = tk.Label(app, text="Username:")
label_username.pack(pady=5)
entry_username = tk.Entry(app)
entry_username.pack(pady=5)

# Password label and entry
label_password = tk.Label(app, text="Password:")
label_password.pack(pady=5)
entry_password = tk.Entry(app, show="*")  # Password input is masked
entry_password.pack(pady=5)

# Register button
btn_register = tk.Button(app, text="Register", command=register_user)
btn_register.pack(pady=5)

# Login button
btn_login = tk.Button(app, text="Login", command=login_user)
btn_login.pack(pady=5)

# Start the application
app.mainloop()
