import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
from backend import (
    register_user, login_user, send_text_message, send_encrypted_file,
    start_receiver, logout_user, is_user_online, stop_receiver
)

gui_user = {"username": None, "password": None, "port": None}
contacts = []  # list[str]
conversations = {}  # dict[str, list[str]]
selected_contact = {"username": None}

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

def attempt_logout():
    if not gui_user["username"]:
        return
    try:
        try:
            stop_receiver()
        except Exception:
            pass
        logout_user(gui_user["username"])
    finally:
        gui_user["username"] = None
        gui_user["password"] = None
        gui_user["port"] = None
        status_label.config(text="Not logged in", fg="red")
        # Clear chat UI
        contacts.clear()
        conversations.clear()
        selected_contact["username"] = None
        refresh_contacts_list()
        chat_box.config(state=tk.NORMAL)
        chat_box.delete(1.0, tk.END)
        msg_frame.pack_forget()

def send_message():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    if not selected_contact["username"]:
        return messagebox.showwarning("Select chat", "Select a user from the chat list.")
    try:
        recipient = selected_contact["username"]
        msg = msg_entry.get()
        if not msg.strip():
            return
        send_text_message(gui_user["username"], gui_user["password"], recipient, msg)
        # store and render
        conversations.setdefault(recipient, []).append(f"You: {msg}")
        if selected_contact["username"] == recipient:
            chat_box.insert(tk.END, f"You: {msg}\n")
        msg_entry.delete(0, tk.END)
    except Exception as e:
        messagebox.showerror("Send Failed", str(e))

def send_file():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    if not selected_contact["username"]:
        return messagebox.showwarning("Select chat", "Select a user from the chat list.")
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            recipient = selected_contact["username"]
            send_encrypted_file(gui_user["username"], gui_user["password"], recipient, file_path)
            conversations.setdefault(recipient, []).append(f"You sent a file: {file_path}")
            if selected_contact["username"] == recipient:
                chat_box.insert(tk.END, f"You sent a file: {file_path}\n")
        except Exception as e:
            messagebox.showerror("Send File Failed", str(e))

# ===== Backend→GUI callbacks =====
def add_contact(username):
    if username not in contacts:
        contacts.append(username)
        conversations.setdefault(username, [])
        refresh_contacts_list()

def on_message_received(sender, message):
    add_contact(sender)
    conversations.setdefault(sender, []).append(f"{sender}: {message}")
    if selected_contact["username"] == sender:
        chat_box.insert(tk.END, f"{sender}: {message}\n")

def on_file_received(sender, filepath):
    add_contact(sender)
    conversations.setdefault(sender, []).append(f"{sender} sent a file: {filepath}")
    if selected_contact["username"] == sender:
        chat_box.insert(tk.END, f"{sender} sent a file: {filepath}\n")

# ===== GUI =====
root = tk.Tk()
root.title("Secure Messaging GUI")
root.geometry("800x550")

top_bar = tk.Frame(root)
top_bar.pack(fill=tk.X, pady=6)

# Credentials (no IP/Port fields)
user_entry = tk.Entry(top_bar, width=20)
pass_entry = tk.Entry(top_bar, show="*", width=20)
user_entry.insert(0, "Username")
pass_entry.insert(0, "Password")
user_entry.grid(row=0, column=0, padx=4)
pass_entry.grid(row=0, column=1, padx=4)

tk.Button(top_bar, text="Register", command=attempt_register).grid(row=0, column=2, padx=4)
tk.Button(top_bar, text="Login", command=attempt_login).grid(row=0, column=3, padx=4)
tk.Button(top_bar, text="Logout", command=attempt_logout).grid(row=0, column=4, padx=4)

status_label = tk.Label(root, text="Not logged in", fg="red")
status_label.pack(anchor="w", padx=8)

main_area = tk.Frame(root)
main_area.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

# Left: contacts list
left_frame = tk.Frame(main_area, width=220)
left_frame.pack(side=tk.LEFT, fill=tk.Y)
left_label = tk.Label(left_frame, text="Chats")
left_label.pack(anchor="w")
contacts_listbox = tk.Listbox(left_frame, width=30, height=25)
contacts_listbox.pack(fill=tk.Y, expand=True)

def new_chat_prompt():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    name = simpledialog.askstring("New Chat", "Enter recipient username:", parent=root)
    if not name:
        return
    name = name.strip()
    if not name or name == gui_user["username"]:
        return
    add_contact(name)
    selected_contact["username"] = name
    refresh_contacts_list()
    if name in contacts:
        idx = contacts.index(name)
        contacts_listbox.selection_clear(0, tk.END)
        contacts_listbox.selection_set(idx)
    # Show chat area
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)
    for line in conversations.get(name, []):
        chat_box.insert(tk.END, line + "\n")
    msg_frame.pack(fill=tk.X, padx=0, pady=4)

tk.Button(left_frame, text="New Chat", command=new_chat_prompt).pack(anchor="w", pady=4)

def refresh_contacts_list():
    # Preserve selection
    current_sel = contacts_listbox.curselection()
    selected_name = selected_contact["username"]
    contacts_listbox.delete(0, tk.END)
    for name in contacts:
        status = "🟢" if is_user_online(name) else "⚪"
        contacts_listbox.insert(tk.END, f"{status} {name}")
    # Restore selection by name
    if selected_name and selected_name in contacts:
        idx = contacts.index(selected_name)
        contacts_listbox.selection_set(idx)

def on_select_contact(event):
    if not contacts_listbox.curselection():
        return
    idx = contacts_listbox.curselection()[0]
    name = contacts[idx]
    selected_contact["username"] = name
    # Render conversation
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)
    for line in conversations.get(name, []):
        chat_box.insert(tk.END, line + "\n")
    chat_box.config(state=tk.NORMAL)
    # Show message bar
    msg_frame.pack(fill=tk.X, padx=0, pady=4)

contacts_listbox.bind('<<ListboxSelect>>', on_select_contact)

# Right: chat area
right_frame = tk.Frame(main_area)
right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

chat_box = scrolledtext.ScrolledText(right_frame, width=60, height=25)
chat_box.pack(fill=tk.BOTH, expand=True)

msg_frame = tk.Frame(right_frame)
msg_entry = tk.Entry(msg_frame, width=60)
msg_entry.insert(0, "Enter message")
msg_entry.grid(row=0, column=0, padx=4)
tk.Button(msg_frame, text="Send", command=send_message).grid(row=0, column=1, padx=4)
tk.Button(msg_frame, text="Send File", command=send_file).grid(row=0, column=2, padx=4)

# Hide message frame until a chat is selected
msg_frame.pack_forget()

def scheduled_presence_refresh():
    if gui_user["username"]:
        refresh_contacts_list()
    root.after(3000, scheduled_presence_refresh)

scheduled_presence_refresh()

def on_close():
    try:
        attempt_logout()
    finally:
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
