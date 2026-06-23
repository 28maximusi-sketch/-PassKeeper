// passkeeper.js
#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ANSI colors
const COLORS = {
    green: '\x1b[92m',
    red: '\x1b[91m',
    yellow: '\x1b[93m',
    blue: '\x1b[94m',
    reset: '\x1b[0m'
};

function colorize(text, color) {
    return COLORS[color] + text + COLORS.reset;
}

const DB_FILE = path.join(os.homedir(), '.passkeeper.db');
const SALT_LEN = 16;
const ITERATIONS = 100000;
const KEY_LEN = 32;

function loadDB() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
    }
}

function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');
}

function encryptData(data, password, salt) {
    const key = deriveKey(password, salt);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = JSON.stringify(data);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptData(encryptedBase64, password, salt) {
    const key = deriveKey(password, salt);
    const raw = Buffer.from(encryptedBase64, 'base64');
    const iv = raw.slice(0, 12);
    const tag = raw.slice(12, 28);
    const encrypted = raw.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
}

function main() {
    const args = process.argv.slice(2);
    if (args.length < 1) {
        console.log(colorize('Usage: passkeeper.js <command> [args...]', 'yellow'));
        console.log('Commands: master, add, get, list, del');
        process.exit(1);
    }
    const cmd = args[0].toLowerCase();

    if (cmd === 'master') {
        if (args.length < 2) {
            console.log(colorize('Usage: passkeeper.js master <new_password> [old_password]', 'yellow'));
            process.exit(1);
        }
        const newPass = args[1];
        let db = loadDB();
        if (!db) {
            // New DB
            const salt = crypto.randomBytes(SALT_LEN);
            const encrypted = encryptData({}, newPass, salt);
            db = { salt: salt.toString('base64'), data: encrypted };
            saveDB(db);
            console.log(colorize('Master password set successfully (new database).', 'green'));
        } else {
            // Change master
            if (args.length < 3) {
                console.log(colorize('To change master password, provide old password: passkeeper.js master <new> <old>', 'yellow'));
                process.exit(1);
            }
            const oldPass = args[2];
            const salt = Buffer.from(db.salt, 'base64');
            let entries;
            try {
                entries = decryptData(db.data, oldPass, salt);
            } catch (e) {
                console.log(colorize('Invalid old master password.', 'red'));
                process.exit(1);
            }
            const newSalt = crypto.randomBytes(SALT_LEN);
            const newEncrypted = encryptData(entries, newPass, newSalt);
            db.salt = newSalt.toString('base64');
            db.data = newEncrypted;
            saveDB(db);
            console.log(colorize('Master password changed successfully.', 'green'));
        }
        return;
    }

    // Other commands
    const db = loadDB();
    if (!db) {
        console.log(colorize('Database not initialized. Set master password first using "master" command.', 'red'));
        process.exit(1);
    }
    if (args.length < 2) {
        console.log(colorize('Master password required.', 'yellow'));
        process.exit(1);
    }
    const masterPass = args[1];
    const salt = Buffer.from(db.salt, 'base64');
    let entries;
    try {
        entries = decryptData(db.data, masterPass, salt);
    } catch (e) {
        console.log(colorize('Invalid master password.', 'red'));
        process.exit(1);
    }
    const cmdArgs = args.slice(2);

    switch (cmd) {
        case 'add':
            if (cmdArgs.length < 3) {
                console.log(colorize('Usage: passkeeper.js add <name> <login> <password> [url]', 'yellow'));
                process.exit(1);
            }
            const [name, login, pwd, url] = cmdArgs;
            if (entries[name]) {
                console.log(colorize('Entry already exists. Use del first.', 'red'));
                process.exit(1);
            }
            entries[name] = { login, password: pwd, url: url || '' };
            db.data = encryptData(entries, masterPass, salt);
            saveDB(db);
            console.log(colorize(`Entry '${name}' added.`, 'green'));
            break;

        case 'get':
            if (cmdArgs.length < 1) {
                console.log(colorize('Usage: passkeeper.js get <name>', 'yellow'));
                process.exit(1);
            }
            const getName = cmdArgs[0];
            const entry = entries[getName];
            if (!entry) {
                console.log(colorize('Entry not found.', 'red'));
                process.exit(1);
            }
            console.log(`Login: ${entry.login}`);
            console.log(`Password: ${entry.password}`);
            if (entry.url) console.log(`URL: ${entry.url}`);
            break;

        case 'list':
            if (Object.keys(entries).length === 0) {
                console.log(colorize('No entries.', 'yellow'));
            } else {
                Object.keys(entries).sort().forEach(name => console.log(name));
            }
            break;

        case 'del':
            if (cmdArgs.length < 1) {
                console.log(colorize('Usage: passkeeper.js del <name>', 'yellow'));
                process.exit(1);
            }
            const delName = cmdArgs[0];
            if (!entries[delName]) {
                console.log(colorize('Entry not found.', 'red'));
                process.exit(1);
            }
            delete entries[delName];
            db.data = encryptData(entries, masterPass, salt);
            saveDB(db);
            console.log(colorize(`Entry '${delName}' deleted.`, 'green'));
            break;

        default:
            console.log(colorize(`Unknown command: ${cmd}`, 'red'));
            console.log('Available: master, add, get, list, del');
            process.exit(1);
    }
}

main();
