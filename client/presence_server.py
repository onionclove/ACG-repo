from flask import Flask, request, jsonify
app = Flask(__name__)

REG = {}  # username -> {"ip": "...", "port": 1234}

@app.post("/register")
def register():
    data = request.get_json()
    username = data["username"]
    port = int(data["port"])
    # Use server-seen IP (safer than trusting the client)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    REG[username] = {"ip": ip, "port": port}
    return {"ok": True}

@app.get("/lookup/<username>")
def lookup(username):
    info = REG.get(username)
    if not info:
        return jsonify({"error": "not found"}), 404
    return info

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8088)