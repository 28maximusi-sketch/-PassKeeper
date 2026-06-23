// passkeeper.java
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import com.google.gson.*; // requires gson

public class passkeeper {
    private static final String DB_FILE = System.getProperty("user.home") + "/.passkeeper.db";
    private static final int SALT_LEN = 16;
    private static final int ITERATIONS = 100000;
    private static final int KEY_LEN = 32;

    private static final String RESET = "\u001B[0m";
    private static final String GREEN = "\u001B[92m";
    private static final String RED = "\u001B[91m";
    private static final String YELLOW = "\u001B[93m";
    private static final String BLUE = "\u001B[94m";

    private static String colorize(String text, String color) {
        return color + text + RESET;
    }

    private static byte[] deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN * 8);
        SecretKey tmp = factory.generateSecret(spec);
        return tmp.getEncoded();
    }

    private static String encryptData(Map<String, Object> data, String password, byte[] salt) throws Exception {
        byte[] key = deriveKey(password, salt);
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        GcmParameterSpec gcmSpec = new GcmParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), gcmSpec);
        String plaintext = new Gson().toJson(data);
        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plainBytes);
        byte[] tag = ciphertext.length > 16 ? Arrays.copyOfRange(ciphertext, ciphertext.length-16, ciphertext.length) : new byte[0];
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    private static Map<String, Object> decryptData(String encrypted, String password, byte[] salt) throws Exception {
        byte[] key = deriveKey(password, salt);
        byte[] combined = Base64.getDecoder().decode(encrypted);
        byte[] iv = Arrays.copyOfRange(combined, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(combined, 12, combined.length);
        GcmParameterSpec gcmSpec = new GcmParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), gcmSpec);
        byte[] plainBytes = cipher.doFinal(ciphertext);
        String plaintext = new String(plainBytes, StandardCharsets.UTF_8);
        Gson gson = new Gson();
        Type type = new com.google.gson.reflect.TypeToken<Map<String, Object>>(){}.getType();
        return gson.fromJson(plaintext, type);
    }

    private static Map<String, Object> loadDB() throws IOException {
        Path path = Paths.get(DB_FILE);
        if (!Files.exists(path)) return null;
        String json = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        Gson gson = new Gson();
        Type type = new com.google.gson.reflect.TypeToken<Map<String, Object>>(){}.getType();
        return gson.fromJson(json, type);
    }

    private static void saveDB(Map<String, Object> db) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(db);
        Files.write(Paths.get(DB_FILE), json.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println(colorize("Usage: passkeeper <command> [args...]", YELLOW));
            System.out.println("Commands: master, add, get, list, del");
            return;
        }
        String cmd = args[0].toLowerCase();

        if (cmd.equals("master")) {
            if (args.length < 2) {
                System.out.println(colorize("Usage: passkeeper master <new_password> [old_password]", YELLOW));
                return;
            }
            String newPass = args[1];
            Map<String, Object> db = loadDB();
            if (db == null) {
                byte[] salt = new byte[SALT_LEN];
                SecureRandom.getInstanceStrong().nextBytes(salt);
                Map<String, Object> empty = new HashMap<>();
                String encrypted = encryptData(empty, newPass, salt);
                db = new HashMap<>();
                db.put("salt", Base64.getEncoder().encodeToString(salt));
                db.put("data", encrypted);
                saveDB(db);
                System.out.println(colorize("Master password set successfully (new database).", GREEN));
            } else {
                if (args.length < 3) {
                    System.out.println(colorize("To change master password, provide old password: passkeeper master <new> <old>", YELLOW));
                    return;
                }
                String oldPass = args[2];
                byte[] salt = Base64.getDecoder().decode((String)db.get("salt"));
                Map<String, Object> entries;
                try {
                    entries = decryptData((String)db.get("data"), oldPass, salt);
                } catch (Exception e) {
                    System.out.println(colorize("Invalid old master password.", RED));
                    return;
                }
                byte[] newSalt = new byte[SALT_LEN];
                SecureRandom.getInstanceStrong().nextBytes(newSalt);
                String newEncrypted = encryptData(entries, newPass, newSalt);
                db.put("salt", Base64.getEncoder().encodeToString(newSalt));
                db.put("data", newEncrypted);
                saveDB(db);
                System.out.println(colorize("Master password changed successfully.", GREEN));
            }
            return;
        }

        Map<String, Object> db2 = loadDB();
        if (db2 == null) {
            System.out.println(colorize("Database not initialized. Set master password first using 'master' command.", RED));
            return;
        }
        if (args.length < 2) {
            System.out.println(colorize("Master password required.", YELLOW));
            return;
        }
        String masterPass = args[1];
        byte[] salt2 = Base64.getDecoder().decode((String)db2.get("salt"));
        Map<String, Object> entries2;
        try {
            entries2 = decryptData((String)db2.get("data"), masterPass, salt2);
        } catch (Exception e) {
            System.out.println(colorize("Invalid master password.", RED));
            return;
        }

        List<String> cmdArgs = new ArrayList<>();
        for (int i = 2; i < args.length; i++) cmdArgs.add(args[i]);

        if (cmd.equals("add")) {
            if (cmdArgs.size() < 3) {
                System.out.println(colorize("Usage: passkeeper add <name> <login> <password> [url]", YELLOW));
                return;
            }
            String name = cmdArgs.get(0), login = cmdArgs.get(1), pwd = cmdArgs.get(2);
            String url = cmdArgs.size() > 3 ? cmdArgs.get(3) : "";
            if (entries2.containsKey(name)) {
                System.out.println(colorize("Entry already exists. Use del first.", RED));
                return;
            }
            Map<String, Object> entry = new HashMap<>();
            entry.put("login", login);
            entry.put("password", pwd);
            if (!url.isEmpty()) entry.put("url", url);
            entries2.put(name, entry);
            db2.put("data", encryptData(entries2, masterPass, salt2));
            saveDB(db2);
            System.out.println(colorize("Entry '" + name + "' added.", GREEN));
        } else if (cmd.equals("get")) {
            if (cmdArgs.size() < 1) {
                System.out.println(colorize("Usage: passkeeper get <name>", YELLOW));
                return;
            }
            String name = cmdArgs.get(0);
            if (!entries2.containsKey(name)) {
                System.out.println(colorize("Entry not found.", RED));
                return;
            }
            Map<String, Object> entry = (Map<String, Object>) entries2.get(name);
            System.out.println("Login: " + entry.get("login"));
            System.out.println("Password: " + entry.get("password"));
            if (entry.containsKey("url")) System.out.println("URL: " + entry.get("url"));
        } else if (cmd.equals("list")) {
            if (entries2.isEmpty())
                System.out.println(colorize("No entries.", YELLOW));
            else {
                List<String> names = new ArrayList<>(entries2.keySet());
                Collections.sort(names);
                for (String n : names) System.out.println(n);
            }
        } else if (cmd.equals("del")) {
            if (cmdArgs.size() < 1) {
                System.out.println(colorize("Usage: passkeeper del <name>", YELLOW));
                return;
            }
            String name = cmdArgs.get(0);
            if (!entries2.containsKey(name)) {
                System.out.println(colorize("Entry not found.", RED));
                return;
            }
            entries2.remove(name);
            db2.put("data", encryptData(entries2, masterPass, salt2));
            saveDB(db2);
            System.out.println(colorize("Entry '" + name + "' deleted.", GREEN));
        } else {
            System.out.println(colorize("Unknown command: " + cmd, RED));
            System.out.println("Available: master, add, get, list, del");
        }
    }
}
