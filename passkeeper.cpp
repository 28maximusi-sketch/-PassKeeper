// passkeeper.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <json/json.h> // requires jsoncpp (sudo apt install libjsoncpp-dev)

using namespace std;

// ANSI colors
const string RESET = "\033[0m";
const string GREEN = "\033[92m";
const string RED = "\033[91m";
const string YELLOW = "\033[93m";
const string BLUE = "\033[94m";

string colorize(const string& text, const string& color) {
    return color + text + RESET;
}

const string DB_FILE = string(getenv("HOME")) + "/.passkeeper.db";
const int SALT_LEN = 16;
const int ITERATIONS = 100000;
const int KEY_LEN = 32;

string base64_encode(const unsigned char* data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

string base64_decode(const string& encoded) {
    BIO *bio, *b64;
    char* buffer = new char[encoded.size()];
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.c_str(), encoded.size());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer, encoded.size());
    BIO_free_all(bio);
    string result(buffer, len);
    delete[] buffer;
    return result;
}

string derive_key(const string& password, const string& salt) {
    unsigned char key[KEY_LEN];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                      (const unsigned char*)salt.c_str(), salt.size(),
                      ITERATIONS, EVP_sha256(), KEY_LEN, key);
    return string((char*)key, KEY_LEN);
}

string encrypt_data(const Json::Value& data, const string& password, const string& salt) {
    string key = derive_key(password, salt);
    unsigned char iv[12];
    if (!RAND_bytes(iv, 12)) throw runtime_error("RAND_bytes failed");

    Json::FastWriter writer;
    string plaintext = writer.write(data);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, (unsigned char*)key.c_str(), iv);
    int len;
    vector<unsigned char> ciphertext(plaintext.size() + 16);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Combine iv + tag + ciphertext
    string result;
    result.append((char*)iv, 12);
    result.append((char*)tag, 16);
    result.append((char*)ciphertext.data(), ciphertext_len);
    return base64_encode((unsigned char*)result.c_str(), result.size());
}

Json::Value decrypt_data(const string& encrypted, const string& password, const string& salt) {
    string key = derive_key(password, salt);
    string raw = base64_decode(encrypted);
    if (raw.size() < 28) throw runtime_error("Invalid encrypted data");
    unsigned char iv[12], tag[16];
    memcpy(iv, raw.c_str(), 12);
    memcpy(tag, raw.c_str() + 12, 16);
    string ciphertext = raw.substr(28);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, (unsigned char*)key.c_str(), iv);
    int len;
    vector<unsigned char> plaintext(ciphertext.size());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.c_str(), ciphertext.size());
    int plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret <= 0) throw runtime_error("Decryption failed");
    plaintext_len += len;

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(string((char*)plaintext.data(), plaintext_len), root))
        throw runtime_error("JSON parse error");
    return root;
}

Json::Value load_db() {
    ifstream f(DB_FILE);
    if (!f) return Json::Value::null;
    Json::Value root;
    f >> root;
    return root;
}

void save_db(const Json::Value& db) {
    ofstream f(DB_FILE);
    f << db;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << colorize("Usage: passkeeper <command> [args...]", YELLOW) << endl;
        cout << "Commands: master, add, get, list, del" << endl;
        return 1;
    }
    string cmd = argv[1];

    if (cmd == "master") {
        if (argc < 3) {
            cout << colorize("Usage: passkeeper master <new_password> [old_password]", YELLOW) << endl;
            return 1;
        }
        string newPass = argv[2];
        Json::Value db = load_db();
        if (db.isNull()) {
            // New DB
            unsigned char salt_bytes[SALT_LEN];
            if (!RAND_bytes(salt_bytes, SALT_LEN)) { cout << colorize("RAND_bytes failed", RED) << endl; return 1; }
            string salt((char*)salt_bytes, SALT_LEN);
            Json::Value empty(Json::objectValue);
            string encrypted = encrypt_data(empty, newPass, salt);
            db["salt"] = base64_encode(salt_bytes, SALT_LEN);
            db["data"] = encrypted;
            save_db(db);
            cout << colorize("Master password set successfully (new database).", GREEN) << endl;
        } else {
            // Change master
            if (argc < 4) {
                cout << colorize("To change master password, provide old password: passkeeper master <new> <old>", YELLOW) << endl;
                return 1;
            }
            string oldPass = argv[3];
            string salt = base64_decode(db["salt"].asString());
            Json::Value entries;
            try {
                entries = decrypt_data(db["data"].asString(), oldPass, salt);
            } catch (...) {
                cout << colorize("Invalid old master password.", RED) << endl;
                return 1;
            }
            unsigned char new_salt_bytes[SALT_LEN];
            if (!RAND_bytes(new_salt_bytes, SALT_LEN)) { cout << colorize("RAND_bytes failed", RED) << endl; return 1; }
            string newSalt((char*)new_salt_bytes, SALT_LEN);
            string newEncrypted = encrypt_data(entries, newPass, newSalt);
            db["salt"] = base64_encode(new_salt_bytes, SALT_LEN);
            db["data"] = newEncrypted;
            save_db(db);
            cout << colorize("Master password changed successfully.", GREEN) << endl;
        }
        return 0;
    }

    // Other commands
    Json::Value db = load_db();
    if (db.isNull()) {
        cout << colorize("Database not initialized. Set master password first using 'master' command.", RED) << endl;
        return 1;
    }
    if (argc < 3) {
        cout << colorize("Master password required.", YELLOW) << endl;
        return 1;
    }
    string masterPass = argv[2];
    string salt = base64_decode(db["salt"].asString());
    Json::Value entries;
    try {
        entries = decrypt_data(db["data"].asString(), masterPass, salt);
    } catch (...) {
        cout << colorize("Invalid master password.", RED) << endl;
        return 1;
    }

    vector<string> args;
    for (int i = 3; i < argc; ++i) args.push_back(argv[i]);

    if (cmd == "add") {
        if (args.size() < 3) {
            cout << colorize("Usage: passkeeper add <name> <login> <password> [url]", YELLOW) << endl;
            return 1;
        }
        string name = args[0], login = args[1], pwd = args[2];
        string url = args.size() > 3 ? args[3] : "";
        if (entries.isMember(name)) {
            cout << colorize("Entry already exists. Use del first.", RED) << endl;
            return 1;
        }
        Json::Value entry;
        entry["login"] = login;
        entry["password"] = pwd;
        if (!url.empty()) entry["url"] = url;
        entries[name] = entry;
        db["data"] = encrypt_data(entries, masterPass, salt);
        save_db(db);
        cout << colorize("Entry '" + name + "' added.", GREEN) << endl;
    } else if (cmd == "get") {
        if (args.size() < 1) {
            cout << colorize("Usage: passkeeper get <name>", YELLOW) << endl;
            return 1;
        }
        string name = args[0];
        if (!entries.isMember(name)) {
            cout << colorize("Entry not found.", RED) << endl;
            return 1;
        }
        Json::Value entry = entries[name];
        cout << "Login: " << entry["login"].asString() << endl;
        cout << "Password: " << entry["password"].asString() << endl;
        if (entry.isMember("url")) cout << "URL: " << entry["url"].asString() << endl;
    } else if (cmd == "list") {
        if (entries.empty()) {
            cout << colorize("No entries.", YELLOW) << endl;
        } else {
            for (auto& key : entries.getMemberNames()) cout << key << endl;
        }
    } else if (cmd == "del") {
        if (args.size() < 1) {
            cout << colorize("Usage: passkeeper del <name>", YELLOW) << endl;
            return 1;
        }
        string name = args[0];
        if (!entries.isMember(name)) {
            cout << colorize("Entry not found.", RED) << endl;
            return 1;
        }
        entries.removeMember(name);
        db["data"] = encrypt_data(entries, masterPass, salt);
        save_db(db);
        cout << colorize("Entry '" + name + "' deleted.", GREEN) << endl;
    } else {
        cout << colorize("Unknown command: " + cmd, RED) << endl;
        cout << "Available: master, add, get, list, del" << endl;
        return 1;
    }
    return 0;
}
