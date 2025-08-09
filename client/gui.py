import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from backend import (
    register_user, login_user, send_text_message, send_encrypted_file,
    start_receiver
)

gui_user = {"username": None, "password": None, "port": None}

# ===== Callbacks =====
def attempt_register():
    try:
        username = user_entry.get().strip()
        password = pass_entry.get()
        register_user(username, password)
        messagebox.showinfo("Success", "Registered successfully.")
    except Exception as e:
        messagebox.showerror("Registration Failed", str(e))

def attempt_login():
    try:
        username = user_entry.get().strip()
        password = pass_entry.get()
        login_user(username, password)  # only verifies creds

        # Start receiver (auto bind + register presence in DB)
        bound_port = start_receiver(username, password, on_message_received, on_file_received)

        gui_user["username"] = username
        gui_user["password"] = password
        gui_user["port"] = bound_port
        status_label.config(text=f"Logged in as {username} (listening on :{bound_port})", fg="green")
    except Exception as e:
        messagebox.showerror("Login Failed", str(e))

def send_message():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    try:
        recipient = to_entry.get().strip()
        msg = msg_entry.get()
        if not recipient:
            return messagebox.showwarning("Recipient required", "Enter a recipient username.")
        send_text_message(gui_user["username"], gui_user["password"], recipient, msg)
        chat_box.insert(tk.END, f"You -> {recipient}: {msg}\n")
        msg_entry.delete(0, tk.END)
    except Exception as e:
        messagebox.showerror("Send Failed", str(e))

def send_file():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            recipient = to_entry.get().strip()
            if not recipient:
                return messagebox.showwarning("Recipient required", "Enter a recipient username.")
            send_encrypted_file(gui_user["username"], gui_user["password"], recipient, file_path)
            chat_box.insert(tk.END, f"You sent a file to {recipient}: {file_path}\n")
        except Exception as e:
            messagebox.showerror("Send File Failed", str(e))

# ===== Backend→GUI callbacks =====
def on_message_received(sender, message):
    chat_box.insert(tk.END, f"{sender}: {message}\n")

def on_file_received(sender, filepath):
    chat_box.insert(tk.END, f"{sender} sent you a file: {filepath}\n")

# ===== GUI =====
root = tk.Tk()
root.title("Secure Messaging GUI")
root.geometry("600x500")

frame = tk.Frame(root)
frame.pack(pady=10)

# Credentials (no IP/Port fields)
user_entry = tk.Entry(frame, width=20)
pass_entry = tk.Entry(frame, show="*", width=20)
user_entry.insert(0, "Username")
pass_entry.insert(0, "Password")
user_entry.grid(row=0, column=0, padx=4)
pass_entry.grid(row=0, column=1, padx=4)

tk.Button(frame, text="Register", command=attempt_register).grid(row=0, column=2, padx=4)
tk.Button(frame, text="Login", command=attempt_login).grid(row=0, column=3, padx=4)

status_label = tk.Label(root, text="Not logged in", fg="red")
status_label.pack()

chat_box = scrolledtext.ScrolledText(root, width=70, height=20)
chat_box.pack(pady=10)

msg_frame = tk.Frame(root)
msg_frame.pack()
to_entry = tk.Entry(msg_frame, width=22)
to_entry.insert(0, "Recipient username")
msg_entry = tk.Entry(msg_frame, width=40)
msg_entry.insert(0, "Enter message")

to_entry.grid(row=0, column=0, padx=4)
msg_entry.grid(row=0, column=1, padx=4)
tk.Button(msg_frame, text="Send", command=send_message).grid(row=0, column=2, padx=4)
tk.Button(msg_frame, text="Send File", command=send_file).grid(row=0, column=3, padx=4)

root.mainloop()
