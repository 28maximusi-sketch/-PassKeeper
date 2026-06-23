// passkeeper.cs
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json; // Install-Package Newtonsoft.Json

class PassKeeper
{
    static string Colorize(string text, string color)
    {
        string col = color switch
        {
            "green" => "\x1b[92m",
            "red" => "\x1b[91m",
            "yellow" => "\x1b[93m",
            "blue" => "\x1b[94m",
            _ => "\x1b[0m"
        };
        return col + text + "\x1b[0m";
    }

    static string DB_FILE = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".passkeeper.db");
    const int SALT_LEN = 16;
    const int ITERATIONS = 100000;
    const int KEY_LEN = 32;

    static byte[] DeriveKey(string password, byte[] salt)
    {
        using (var rfc = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256))
            return rfc.GetBytes(KEY_LEN);
    }

    static string EncryptData(object data, string password, byte[] salt)
    {
        byte[] key = DeriveKey(password, salt);
        byte[] iv = new byte[12];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(iv);
        string plaintext = JsonConvert.SerializeObject(data);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
        using (var aes = new AesGcm(key))
        {
            byte[] ciphertext = new byte[plainBytes.Length];
            byte[] tag = new byte[16];
            aes.Encrypt(iv, plainBytes, ciphertext, tag);
            byte[] combined = new byte[iv.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(tag, 0, combined, iv.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, combined, iv.Length + tag.Length, ciphertext.Length);
            return Convert.ToBase64String(combined);
        }
    }

    static T DecryptData<T>(string encrypted, string password, byte[] salt)
    {
        byte[] key = DeriveKey(password, salt);
        byte[] combined = Convert.FromBase64String(encrypted);
        byte[] iv = new byte[12];
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[combined.Length - 28];
        Buffer.BlockCopy(combined, 0, iv, 0, 12);
        Buffer.BlockCopy(combined, 12, tag, 0, 16);
        Buffer.BlockCopy(combined, 28, ciphertext, 0, ciphertext.Length);
        byte[] plainBytes = new byte[ciphertext.Length];
        using (var aes = new AesGcm(key))
        {
            aes.Decrypt(iv, ciphertext, tag, plainBytes);
        }
        string plaintext = Encoding.UTF8.GetString(plainBytes);
        return JsonConvert.DeserializeObject<T>(plaintext);
    }

    static Dictionary<string, object> LoadDB()
    {
        if (!File.Exists(DB_FILE)) return null;
        string json = File.ReadAllText(DB_FILE);
        return JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
    }

    static void SaveDB(Dictionary<string, object> db)
    {
        string json = JsonConvert.SerializeObject(db, Formatting.Indented);
        File.WriteAllText(DB_FILE, json);
    }

    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine(Colorize("Usage: passkeeper <command> [args...]", "yellow"));
            Console.WriteLine("Commands: master, add, get, list, del");
            return;
        }
        string cmd = args[0].ToLower();

        if (cmd == "master")
        {
            if (args.Length < 2)
            {
                Console.WriteLine(Colorize("Usage: passkeeper master <new_password> [old_password]", "yellow"));
                return;
            }
            string newPass = args[1];
            var db = LoadDB();
            if (db == null)
            {
                // New DB
                byte[] salt = new byte[SALT_LEN];
                using (var rng = RandomNumberGenerator.Create())
                    rng.GetBytes(salt);
                var empty = new Dictionary<string, object>();
                string encrypted = EncryptData(empty, newPass, salt);
                db = new Dictionary<string, object>
                {
                    ["salt"] = Convert.ToBase64String(salt),
                    ["data"] = encrypted
                };
                SaveDB(db);
                Console.WriteLine(Colorize("Master password set successfully (new database).", "green"));
            }
            else
            {
                if (args.Length < 3)
                {
                    Console.WriteLine(Colorize("To change master password, provide old password: passkeeper master <new> <old>", "yellow"));
                    return;
                }
                string oldPass = args[2];
                byte[] salt = Convert.FromBase64String((string)db["salt"]);
                Dictionary<string, object> entries;
                try
                {
                    entries = DecryptData<Dictionary<string, object>>((string)db["data"], oldPass, salt);
                }
                catch
                {
                    Console.WriteLine(Colorize("Invalid old master password.", "red"));
                    return;
                }
                byte[] newSalt = new byte[SALT_LEN];
                using (var rng = RandomNumberGenerator.Create())
                    rng.GetBytes(newSalt);
                string newEncrypted = EncryptData(entries, newPass, newSalt);
                db["salt"] = Convert.ToBase64String(newSalt);
                db["data"] = newEncrypted;
                SaveDB(db);
                Console.WriteLine(Colorize("Master password changed successfully.", "green"));
            }
            return;
        }

        // Other commands
        var db2 = LoadDB();
        if (db2 == null)
        {
            Console.WriteLine(Colorize("Database not initialized. Set master password first using 'master' command.", "red"));
            return;
        }
        if (args.Length < 2)
        {
            Console.WriteLine(Colorize("Master password required.", "yellow"));
            return;
        }
        string masterPass = args[1];
        byte[] salt2 = Convert.FromBase64String((string)db2["salt"]);
        Dictionary<string, object> entries2;
        try
        {
            entries2 = DecryptData<Dictionary<string, object>>((string)db2["data"], masterPass, salt2);
        }
        catch
        {
            Console.WriteLine(Colorize("Invalid master password.", "red"));
            return;
        }

        var cmdArgs = args.Skip(2).ToArray();

        if (cmd == "add")
        {
            if (cmdArgs.Length < 3)
            {
                Console.WriteLine(Colorize("Usage: passkeeper add <name> <login> <password> [url]", "yellow"));
                return;
            }
            string name = cmdArgs[0], login = cmdArgs[1], pwd = cmdArgs[2];
            string url = cmdArgs.Length > 3 ? cmdArgs[3] : "";
            if (entries2.ContainsKey(name))
            {
                Console.WriteLine(Colorize("Entry already exists. Use del first.", "red"));
                return;
            }
            var entry = new Dictionary<string, object> { ["login"] = login, ["password"] = pwd };
            if (!string.IsNullOrEmpty(url)) entry["url"] = url;
            entries2[name] = entry;
            db2["data"] = EncryptData(entries2, masterPass, salt2);
            SaveDB(db2);
            Console.WriteLine(Colorize($"Entry '{name}' added.", "green"));
        }
        else if (cmd == "get")
        {
            if (cmdArgs.Length < 1)
            {
                Console.WriteLine(Colorize("Usage: passkeeper get <name>", "yellow"));
                return;
            }
            string name = cmdArgs[0];
            if (!entries2.ContainsKey(name))
            {
                Console.WriteLine(Colorize("Entry not found.", "red"));
                return;
            }
            var entry = (Dictionary<string, object>)entries2[name];
            Console.WriteLine($"Login: {entry["login"]}");
            Console.WriteLine($"Password: {entry["password"]}");
            if (entry.ContainsKey("url")) Console.WriteLine($"URL: {entry["url"]}");
        }
        else if (cmd == "list")
        {
            if (entries2.Count == 0)
                Console.WriteLine(Colorize("No entries.", "yellow"));
            else
                foreach (var key in entries2.Keys.OrderBy(k => k))
                    Console.WriteLine(key);
        }
        else if (cmd == "del")
        {
            if (cmdArgs.Length < 1)
            {
                Console.WriteLine(Colorize("Usage: passkeeper del <name>", "yellow"));
                return;
            }
            string name = cmdArgs[0];
            if (!entries2.ContainsKey(name))
            {
                Console.WriteLine(Colorize("Entry not found.", "red"));
                return;
            }
            entries2.Remove(name);
            db2["data"] = EncryptData(entries2, masterPass, salt2);
            SaveDB(db2);
            Console.WriteLine(Colorize($"Entry '{name}' deleted.", "green"));
        }
        else
        {
            Console.WriteLine(Colorize($"Unknown command: {cmd}", "red"));
            Console.WriteLine("Available: master, add, get, list, del");
        }
    }
}
