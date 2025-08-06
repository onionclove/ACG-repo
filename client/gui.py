import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from backend import (
    register_user, login_user, send_text_message, send_encrypted_file,
    start_receiver
)

# Globals
gui_user = {"username": None, "password": None}

# === UI CALLBACKS ===
def attempt_register():
    try:
        register_user(user_entry.get(), pass_entry.get())
        messagebox.showinfo("Success", "Registered successfully.")
    except Exception as e:
        messagebox.showerror("Registration Failed", str(e))

def attempt_login():
    try:
        ip = ip_entry.get()
        port = int(port_entry.get())
        login_user(user_entry.get(), pass_entry.get(), ip, port)
        gui_user["username"] = user_entry.get()
        gui_user["password"] = pass_entry.get()
        start_receiver(gui_user["username"], gui_user["password"], ip, port,
                       on_message_received, on_file_received)
        status_label.config(text=f"Logged in as {gui_user['username']}", fg="green")
    except Exception as e:
        messagebox.showerror("Login Failed", str(e))

def send_message():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    try:
        send_text_message(gui_user["username"], gui_user["password"], to_entry.get(), msg_entry.get())
        chat_box.insert(tk.END, f"You -> {to_entry.get()}: {msg_entry.get()}\n")
        msg_entry.delete(0, tk.END)
    except Exception as e:
        messagebox.showerror("Send Failed", str(e))

def send_file():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            send_encrypted_file(gui_user["username"], gui_user["password"], to_entry.get(), file_path)
            chat_box.insert(tk.END, f"You sent a file to {to_entry.get()}: {file_path}\n")
        except Exception as e:
            messagebox.showerror("Send File Failed", str(e))

# === CALLBACKS ===
def on_message_received(sender, message):
    chat_box.insert(tk.END, f"{sender}: {message}\n")

def on_file_received(sender, filepath):
    chat_box.insert(tk.END, f"{sender} sent you a file: {filepath}\n")

# === GUI ===
root = tk.Tk()
root.title("Secure Messaging GUI")
root.geometry("600x500")

frame = tk.Frame(root)
frame.pack(pady=10)

# Credentials
user_entry = tk.Entry(frame, width=15)
pass_entry = tk.Entry(frame, show="*", width=15)
ip_entry = tk.Entry(frame, width=15)
port_entry = tk.Entry(frame, width=6)

user_entry.insert(0, "Username")
pass_entry.insert(0, "Password")
ip_entry.insert(0, "127.0.0.1")
port_entry.insert(0, "5555")

user_entry.grid(row=0, column=0)
pass_entry.grid(row=0, column=1)
ip_entry.grid(row=0, column=2)
port_entry.grid(row=0, column=3)

tk.Button(frame, text="Register", command=attempt_register).grid(row=0, column=4)
tk.Button(frame, text="Login", command=attempt_login).grid(row=0, column=5)

# Status
status_label = tk.Label(root, text="Not logged in", fg="red")
status_label.pack()

# Chat
chat_box = scrolledtext.ScrolledText(root, width=70, height=20)
chat_box.pack(pady=10)

# Message entry
msg_frame = tk.Frame(root)
msg_frame.pack()
to_entry = tk.Entry(msg_frame, width=15)
to_entry.insert(0, "Recipient")
msg_entry = tk.Entry(msg_frame, width=40)
msg_entry.insert(0, "Enter message")

to_entry.grid(row=0, column=0)
msg_entry.grid(row=0, column=1)
tk.Button(msg_frame, text="Send", command=send_message).grid(row=0, column=2)
tk.Button(msg_frame, text="Send File", command=send_file).grid(row=0, column=3)

root.mainloop()
