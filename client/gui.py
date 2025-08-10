# Jingkai, Jotish, Craig, Jerome
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
import threading

from backend import (
    register_user, login_user, logout_user, is_user_online,
    start_receiver, stop_receiver,
    send_text_message, send_text_message_pfs, send_encrypted_file,
    view_pending_for_contact,
    list_all_users, 
    get_chat_history
)

gui_user = {"username": None, "password": None, "port": None, "receiver_started": False}
contacts = []            # list[str]
conversations = {}       # dict[str, list[str]]
selected_contact = {"username": None}
contacts_index = []          # listbox row -> username (None for headers)
_last_render_state = {"hash": None}


# -------------- UI helpers --------------
def ui_call(fn, *args, **kwargs):
    """Ensure UI updates run on Tk main thread."""
    root.after(0, lambda: fn(*args, **kwargs))

def add_contact(name: str):
    if name not in contacts:
        contacts.append(name)
        conversations.setdefault(name, [])
        refresh_contacts_list()

def append_chat_line(name: str, line: str):
    conversations.setdefault(name, []).append(line)
    if selected_contact["username"] == name:
        chat_box.insert(tk.END, line + "\n")
        chat_box.see(tk.END)

def set_logged_in(username: str, bound_port: int):
    gui_user.update(username=username, password=pass_entry.get(), port=bound_port, receiver_started=True)
    status_label.config(text=f"Logged in as {username} (listening on :{bound_port})", fg="green")
    # enable chat controls
    new_chat_btn.config(state=tk.NORMAL)
    send_btn.config(state=tk.NORMAL)
    send_file_btn.config(state=tk.NORMAL)
    logout_btn.config(state=tk.NORMAL)
    login_btn.config(state=tk.DISABLED)
    register_btn.config(state=tk.DISABLED)
    user_entry.config(state=tk.DISABLED)
    pass_entry.config(state=tk.DISABLED)
    try:
        all_users = list_all_users(exclude=username)
        contacts.clear()
        contacts.extend(all_users)
        for u in all_users:
            conversations.setdefault(u, [])   # keep existing chat history dict
        refresh_contacts_list()
    except Exception as e:
        print("Failed to load users:", e)

    

def set_logged_out():
    gui_user.update(username=None, password=None, port=None, receiver_started=False)
    status_label.config(text="Not logged in", fg="red")

    # keep chat history dict; just deselect the open chat
    selected_contact["username"] = None

    # clear chat view
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)
    msg_frame.pack_forget()

    # disable chat controls
    new_chat_btn.config(state=tk.DISABLED)
    send_btn.config(state=tk.DISABLED)
    send_file_btn.config(state=tk.DISABLED)
    logout_btn.config(state=tk.DISABLED)
    login_btn.config(state=tk.NORMAL)
    register_btn.config(state=tk.NORMAL)
    user_entry.config(state=tk.NORMAL)
    pass_entry.config(state=tk.NORMAL)

    # RELOAD roster (no exclude) so it looks like on app start
    try:
        users = list_all_users()
        contacts[:] = users
        for u in users:
            conversations.setdefault(u, [])
        refresh_contacts_list()
    except Exception as e:
        print("Failed to load users on logout:", e)

def clear_placeholder_on_focus(entry, placeholder):
    def _on_focus_in(_):
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
    def _on_focus_out(_):
        if not entry.get().strip():
            entry.insert(0, placeholder)
    entry.bind("<FocusIn>", _on_focus_in)
    entry.bind("<FocusOut>", _on_focus_out)

# -------------- Backend→GUI callbacks (thread-safe) --------------
def on_message_received(sender, message):
    ui_call(add_contact, sender)
    ui_call(append_chat_line, sender, f"{sender}: {message}")

def on_file_received(sender, filepath):
    ui_call(add_contact, sender)
    ui_call(append_chat_line, sender, f"{sender} sent a file: {filepath}")

# -------------- Actions --------------
def attempt_register():
    try:
        username = user_entry.get().strip()
        password = pass_entry.get()
        if not username or username == "Username":
            return messagebox.showwarning("Missing", "Please enter a username.")
        if not password or password == "Password":
            return messagebox.showwarning("Missing", "Please enter a password.")
        register_user(username, password)
        messagebox.showinfo("Success", "Registered successfully.")
    except Exception as e:
        messagebox.showerror("Registration Failed", str(e))

def _start_receiver_in_bg(username, password):
    try:
        bound_port = start_receiver(username, password, on_message_received, on_file_received)
        ui_call(set_logged_in, username, bound_port)
    except Exception as e:
        ui_call(messagebox.showerror, "Receiver Error", str(e))

def attempt_login():
    if gui_user["receiver_started"]:
        return
    try:
        username = user_entry.get().strip()
        password = pass_entry.get()
        if not username or username == "Username":
            return messagebox.showwarning("Missing", "Please enter a username.")
        if not password or password == "Password":
            return messagebox.showwarning("Missing", "Please enter a password.")
        # verify creds (presence is set by start_receiver after bind)
        login_user(username, password)
        # start receiver on a thread (binds port, sets presence, drains queue)
        threading.Thread(target=_start_receiver_in_bg, args=(username, password), daemon=True).start()
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
        set_logged_out()

def send_message():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    if not selected_contact["username"]:
        return messagebox.showwarning("Select chat", "Select a user from the chat list.")
    recipient = selected_contact["username"]
    msg = msg_entry.get()
    if not msg.strip():
        return
    use_pfs = pfs_var.get() == 1

    def _bg():
        try:
            if use_pfs:
                send_text_message_pfs(gui_user["username"], gui_user["password"], recipient, msg)
            else:
                send_text_message(gui_user["username"], gui_user["password"], recipient, msg)
            ui_call(append_chat_line, recipient, f"You: {msg}")
            ui_call(msg_entry.delete, 0, tk.END)
        except Exception as e:
            ui_call(messagebox.showerror, "Send Failed", str(e))

    threading.Thread(target=_bg, daemon=True).start()

def send_file():
    if not gui_user["username"]:
        return messagebox.showwarning("Login required", "Please login first.")
    if not selected_contact["username"]:
        return messagebox.showwarning("Select chat", "Select a user from the chat list.")
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    recipient = selected_contact["username"]

    def _bg():
        try:
            send_encrypted_file(gui_user["username"], gui_user["password"], recipient, file_path)
            ui_call(append_chat_line, recipient, f"You sent a file: {file_path}")
        except Exception as e:
            ui_call(messagebox.showerror, "Send File Failed", str(e))

    threading.Thread(target=_bg, daemon=True).start()

# -------------- GUI --------------
root = tk.Tk()
root.title("Secure Messaging GUI")
root.geometry("860x560")

top_bar = tk.Frame(root)
top_bar.pack(fill=tk.X, pady=6)

user_entry = tk.Entry(top_bar, width=20)
pass_entry = tk.Entry(top_bar, show="*", width=20)
user_entry.insert(0, "Username")
pass_entry.insert(0, "Password")
user_entry.grid(row=0, column=0, padx=4)
pass_entry.grid(row=0, column=1, padx=4)
clear_placeholder_on_focus(user_entry, "Username")
clear_placeholder_on_focus(pass_entry, "Password")

register_btn = tk.Button(top_bar, text="Register", width=10, command=attempt_register)
login_btn = tk.Button(top_bar, text="Login", width=10, command=attempt_login)
logout_btn = tk.Button(top_bar, text="Logout", width=10, command=attempt_logout, state=tk.DISABLED)

register_btn.grid(row=0, column=2, padx=4)
login_btn.grid(row=0, column=3, padx=4)
logout_btn.grid(row=0, column=4, padx=4)

# PFS Toggle
pfs_var = tk.IntVar(value=1)  # default ON
pfs_chk = tk.Checkbutton(top_bar, text="Use PFS", variable=pfs_var)
pfs_chk.grid(row=0, column=5, padx=8)

status_label = tk.Label(root, text="Not logged in", fg="red")
status_label.pack(anchor="w", padx=8)

main_area = tk.Frame(root)
main_area.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

# Left: contacts
left_frame = tk.Frame(main_area, width=240)
left_frame.pack(side=tk.LEFT, fill=tk.Y)
left_label = tk.Label(left_frame, text="Chats")
left_label.pack(anchor="w")

contacts_listbox = tk.Listbox(left_frame, width=32, height=25)
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
    # show chat area
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)
    for line in conversations.get(name, []):
        chat_box.insert(tk.END, line + "\n")
    msg_frame.pack(fill=tk.X, padx=0, pady=4)

new_chat_btn = tk.Button(left_frame, text="New Chat", command=new_chat_prompt, state=tk.DISABLED)
new_chat_btn.pack(anchor="w", pady=4)


def split_online_offline(names):
    online, offline = [], []
    for n in sorted(names, key=str.lower):
        try:
            (online if is_user_online(n) else offline).append(n)
        except Exception:
            offline.append(n)
    return online, offline

def rebuild_contacts_list():
    global contacts_index
    # remember scroll + selection
    y = contacts_listbox.yview()
    prev_selected = None
    if contacts_listbox.curselection():
        prev_idx = contacts_listbox.curselection()[0]
        if 0 <= prev_idx < len(contacts_index):
            prev_selected = contacts_index[prev_idx]

    contacts_listbox.delete(0, tk.END)
    contacts_index = [] 

    online, offline = split_online_offline(contacts)

    def add_header(text):
        contacts_listbox.insert(tk.END, text)
        idx = contacts_listbox.size() - 1
        contacts_index.append(None)
        contacts_listbox.itemconfig(idx, foreground="#888", background="#f0f0f0",
                                    selectforeground="#888", selectbackground="#f0f0f0")

    def add_user(name, online_flag):
        dot = "🟢" if online_flag else "🔴"   # green for online, red for offline
        contacts_listbox.insert(tk.END, f"{dot} {name}")
        contacts_index.append(name)

    add_header("— ONLINE —")
    if online:
        for n in online: add_user(n, True)
    else:
        contacts_listbox.insert(tk.END, "(no one online)")
        contacts_index.append(None)
        contacts_listbox.itemconfig(contacts_listbox.size()-1, foreground="#aaa")

    add_header("— OFFLINE —")
    if offline:
        for n in offline: add_user(n, False)
    else:
        contacts_listbox.insert(tk.END, "(none)")
        contacts_index.append(None)
        contacts_listbox.itemconfig(contacts_listbox.size()-1, foreground="#aaa")

    # restore selection
    if prev_selected:
        for i, uname in enumerate(contacts_index):
            if uname == prev_selected:
                contacts_listbox.selection_clear(0, tk.END)
                contacts_listbox.selection_set(i)
                contacts_listbox.see(i)
                break
    # restore scroll
    contacts_listbox.yview_moveto(y[0])

def refresh_contacts_list():
    online_flags = []
    for n in sorted(contacts, key=str.lower):
        try:
            online_flags.append((n, 1 if is_user_online(n) else 0))
        except Exception:
            online_flags.append((n, 0))
    token = tuple(online_flags)
    if token != _last_render_state["hash"]:
        rebuild_contacts_list()
        _last_render_state["hash"] = token

def on_select_contact(_event):
    if not contacts_listbox.curselection():
        return
    idx = contacts_listbox.curselection()[0]
    uname = contacts_index[idx]
    if uname is None:  # header/placeholder clicked
        contacts_listbox.selection_clear(idx)
        return

    selected_contact["username"] = uname

    # open chat UI
    chat_box.config(state=tk.NORMAL)
    chat_box.delete(1.0, tk.END)
    msg_frame.pack(fill=tk.X, padx=0, pady=4)

    # if not logged in, show hint and disable send
    if not gui_user["username"]:
        send_btn.config(state=tk.DISABLED)
        send_file_btn.config(state=tk.DISABLED)
        chat_box.insert(tk.END, "(Login to view message history and send messages.)\n")
        chat_box.see(tk.END)
        return

    # logged in: enable send
    send_btn.config(state=tk.NORMAL)
    send_file_btn.config(state=tk.NORMAL)

    # load history + pending in background
    def _bg_load():
        try:
            # 1) history from DB
            hist = get_chat_history(
                current_user=gui_user["username"],
                password=gui_user["password"],
                contact=uname,
                limit=500
            )
            def _render_hist():
                conversations.setdefault(uname, [])
                conversations[uname].clear()
                for sender, text, _ts in hist:
                    prefix = "You" if sender == gui_user["username"] else sender
                    line = f"{prefix}: {text}"
                    conversations[uname].append(line)
                    if selected_contact["username"] == uname:
                        chat_box.insert(tk.END, line + "\n")
                chat_box.see(tk.END)
            ui_call(_render_hist)

            # 2) pending (callbacks will append; rows are then moved to messages)
            cnt = view_pending_for_contact(
                current_user=gui_user["username"],
                contact=uname,
                password=gui_user["password"],
                on_message=on_message_received,
                on_file=on_file_received
            )
            if cnt:
                ui_call(append_chat_line, uname, f"(Loaded {cnt} pending messages)")
        except Exception as e:
            print("load history/pending error:", e)

    threading.Thread(target=_bg_load, daemon=True).start()

contacts_listbox.bind('<<ListboxSelect>>', on_select_contact)

# Right: chat area
right_frame = tk.Frame(main_area)
right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

chat_box = scrolledtext.ScrolledText(right_frame, width=60, height=25)
chat_box.pack(fill=tk.BOTH, expand=True)
chat_box.config(state=tk.NORMAL)

msg_frame = tk.Frame(right_frame)

msg_entry = tk.Entry(msg_frame, width=60)
msg_entry.insert(0, "Enter message")
msg_entry.grid(row=0, column=0, padx=4)

send_btn = tk.Button(msg_frame, text="Send", width=10, command=send_message, state=tk.DISABLED)
send_btn.grid(row=0, column=1, padx=4)

send_file_btn = tk.Button(msg_frame, text="Send File", width=10, command=send_file, state=tk.DISABLED)
send_file_btn.grid(row=0, column=2, padx=4)

def on_enter_send(_event):
    if send_btn["state"] == tk.NORMAL:
        send_message()

msg_entry.bind("<Return>", on_enter_send)

# Hidden until a chat is selected
msg_frame.pack_forget()

def scheduled_presence_refresh():
    try:
        refresh_contacts_list()    # refresh even if not logged in
    except Exception as e:
        print("presence refresh:", e)
    root.after(3000, scheduled_presence_refresh)

scheduled_presence_refresh()

def on_close():
    try:
        attempt_logout()
    finally:
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

# start with disabled chat controls
set_logged_out()

try:
    users = list_all_users()         
    contacts.clear()
    contacts.extend(users)
    for u in users:
        conversations.setdefault(u, [])
    refresh_contacts_list()
except Exception as e:
    print("Initial user load failed:", e)

root.mainloop()
