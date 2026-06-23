# passkeeper.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ANSI colors
COLORS = {
    'green': '\033[92m',
    'red': '\033[91m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'reset': '\033[0m'
}

def colorize(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

HOME = os.path.expanduser('~')
DB_FILE = os.path.join(HOME, '.passkeeper.db')
SALT_LEN = 16
ITERATIONS = 100_000

def load_db():
    if not os.path.exists(DB_FILE):
        return None
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITERATIONS)
    return kdf.derive(password.encode('utf-8'))

def encrypt_data(data, password, salt):
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode('ascii')

def decrypt_data(encrypted, password, salt):
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    raw = base64.b64decode(encrypted)
    nonce = raw[:12]
    ciphertext = raw[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

def get_master_password():
    # In real scenario, we'd prompt securely. For simplicity, we read from command line.
    # But we'll pass it via argument.
    pass

def main():
    if len(sys.argv) < 2:
        print(colorize("Usage: passkeeper.py <command> [args...]", 'yellow'))
        print("Commands: master, add, get, list, del")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == 'master':
        if len(sys.argv) < 3:
            print(colorize("Usage: passkeeper.py master <new_password>", 'yellow'))
            sys.exit(1)
        new_pass = sys.argv[2]
        db = load_db()
        if db is None:
            # New database
            salt = secrets.token_bytes(SALT_LEN)
            db = {'salt': base64.b64encode(salt).decode('ascii'), 'data': ''}
            # No data yet
            save_db(db)
            print(colorize("Master password set successfully (new database).", 'green'))
        else:
            # Change master password: need old password
            if len(sys.argv) < 4:
                print(colorize("To change master password, provide old password: passkeeper.py master <new> <old>", 'yellow'))
                sys.exit(1)
            old_pass = sys.argv[3]
            salt = base64.b64decode(db['salt'])
            try:
                decrypt_data(db['data'], old_pass, salt)  # Just to verify
            except Exception:
                print(colorize("Invalid old master password.", 'red'))
                sys.exit(1)
            # Re-encrypt data with new password
            data = decrypt_data(db['data'], old_pass, salt)
            new_salt = secrets.token_bytes(SALT_LEN)
            new_encrypted = encrypt_data(data, new_pass, new_salt)
            db['salt'] = base64.b64encode(new_salt).decode('ascii')
            db['data'] = new_encrypted
            save_db(db)
            print(colorize("Master password changed successfully.", 'green'))
        return

    # Other commands require database and master password
    db = load_db()
    if db is None:
        print(colorize("Database not initialized. Set master password first using 'master' command.", 'red'))
        sys.exit(1)

    # Prompt for master password (we'll get it from argument for simplicity, but in real app would use getpass)
    if len(sys.argv) < 3:
        print(colorize("Master password required for this command.", 'yellow'))
        sys.exit(1)
    master_pass = sys.argv[2]  # We'll shift arguments per command

    salt = base64.b64decode(db['salt'])
    try:
        data = decrypt_data(db['data'], master_pass, salt)
    except Exception:
        print(colorize("Invalid master password.", 'red'))
        sys.exit(1)

    # Remaining arguments
    args = sys.argv[3:]

    if cmd == 'add':
        if len(args) < 3:
            print(colorize("Usage: passkeeper.py add <name> <login> <password> [url]", 'yellow'))
            sys.exit(1)
        name, login, pwd = args[0], args[1], args[2]
        url = args[3] if len(args) > 3 else ''
        if name in data:
            print(colorize("Entry already exists. Use del first or change manually.", 'red'))
            sys.exit(1)
        data[name] = {'login': login, 'password': pwd, 'url': url}
        db['data'] = encrypt_data(data, master_pass, salt)
        save_db(db)
        print(colorize(f"Entry '{name}' added.", 'green'))

    elif cmd == 'get':
        if len(args) < 1:
            print(colorize("Usage: passkeeper.py get <name>", 'yellow'))
            sys.exit(1)
        name = args[0]
        if name not in data:
            print(colorize(f"Entry '{name}' not found.", 'red'))
            sys.exit(1)
        entry = data[name]
        print(f"Login: {entry['login']}")
        print(f"Password: {entry['password']}")
        if entry.get('url'):
            print(f"URL: {entry['url']}")

    elif cmd == 'list':
        if data:
            for name in sorted(data.keys()):
                print(name)
        else:
            print(colorize("No entries.", 'yellow'))

    elif cmd == 'del':
        if len(args) < 1:
            print(colorize("Usage: passkeeper.py del <name>", 'yellow'))
            sys.exit(1)
        name = args[0]
        if name not in data:
            print(colorize(f"Entry '{name}' not found.", 'red'))
            sys.exit(1)
        del data[name]
        db['data'] = encrypt_data(data, master_pass, salt)
        save_db(db)
        print(colorize(f"Entry '{name}' deleted.", 'green'))

    else:
        print(colorize(f"Unknown command: {cmd}", 'red'))
        print("Available: master, add, get, list, del")
        sys.exit(1)

if __name__ == '__main__':
    main()
