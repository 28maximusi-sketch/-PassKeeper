// passkeeper.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ANSI colors
const (
	reset  = "\033[0m"
	green  = "\033[92m"
	red    = "\033[91m"
	yellow = "\033[93m"
	blue   = "\033[94m"
)

func colorize(text, color string) string {
	return color + text + reset
}

const (
	dbFileName = ".passkeeper.db"
	saltLen    = 16
	iterations = 100000
	keyLen     = 32
)

type db struct {
	Salt string `json:"salt"`
	Data string `json:"data"` // encrypted data (base64)
}

type entry struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
}

func getDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, dbFileName)
}

func loadDB() (*db, error) {
	path := getDBPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var db db
	dec := json.NewDecoder(f)
	if err := dec.Decode(&db); err != nil {
		return nil, err
	}
	return &db, nil
}

func saveDB(db *db) error {
	path := getDBPath()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(db)
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

func encryptData(data interface{}, password string, salt []byte) (string, error) {
	key := deriveKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptData(encrypted string, password string, salt []byte) (map[string]entry, error) {
	key := deriveKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var entries map[string]entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(colorize("Usage: passkeeper <command> [args...]", yellow))
		fmt.Println("Commands: master, add, get, list, del")
		os.Exit(1)
	}
	cmd := strings.ToLower(os.Args[1])

	if cmd == "master" {
		if len(os.Args) < 3 {
			fmt.Println(colorize("Usage: passkeeper master <new_password> [old_password]", yellow))
			os.Exit(1)
		}
		newPass := os.Args[2]
		db, err := loadDB()
		if err != nil {
			fmt.Println(colorize("Error loading database: "+err.Error(), red))
			os.Exit(1)
		}
		if db == nil {
			// New DB
			salt := make([]byte, saltLen)
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				fmt.Println(colorize("Error generating salt: "+err.Error(), red))
				os.Exit(1)
			}
			// Empty data
			encrypted, err := encryptData(map[string]entry{}, newPass, salt)
			if err != nil {
				fmt.Println(colorize("Error encrypting: "+err.Error(), red))
				os.Exit(1)
			}
			db = &db{
				Salt: base64.StdEncoding.EncodeToString(salt),
				Data: encrypted,
			}
			if err := saveDB(db); err != nil {
				fmt.Println(colorize("Error saving database: "+err.Error(), red))
				os.Exit(1)
			}
			fmt.Println(colorize("Master password set successfully (new database).", green))
		} else {
			// Change master password
			if len(os.Args) < 4 {
				fmt.Println(colorize("To change master password, provide old password: passkeeper master <new> <old>", yellow))
				os.Exit(1)
			}
			oldPass := os.Args[3]
			salt, err := base64.StdEncoding.DecodeString(db.Salt)
			if err != nil {
				fmt.Println(colorize("Invalid salt", red))
				os.Exit(1)
			}
			entries, err := decryptData(db.Data, oldPass, salt)
			if err != nil {
				fmt.Println(colorize("Invalid old master password.", red))
				os.Exit(1)
			}
			newSalt := make([]byte, saltLen)
			if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
				fmt.Println(colorize("Error generating salt: "+err.Error(), red))
				os.Exit(1)
			}
			encrypted, err := encryptData(entries, newPass, newSalt)
			if err != nil {
				fmt.Println(colorize("Error encrypting: "+err.Error(), red))
				os.Exit(1)
			}
			db.Salt = base64.StdEncoding.EncodeToString(newSalt)
			db.Data = encrypted
			if err := saveDB(db); err != nil {
				fmt.Println(colorize("Error saving database: "+err.Error(), red))
				os.Exit(1)
			}
			fmt.Println(colorize("Master password changed successfully.", green))
		}
		return
	}

	// Other commands need DB and master password
	db, err := loadDB()
	if err != nil {
		fmt.Println(colorize("Error loading database: "+err.Error(), red))
		os.Exit(1)
	}
	if db == nil {
		fmt.Println(colorize("Database not initialized. Set master password first using 'master' command.", red))
		os.Exit(1)
	}
	if len(os.Args) < 3 {
		fmt.Println(colorize("Master password required.", yellow))
		os.Exit(1)
	}
	masterPass := os.Args[2]
	args := os.Args[3:]

	salt, err := base64.StdEncoding.DecodeString(db.Salt)
	if err != nil {
		fmt.Println(colorize("Invalid salt", red))
		os.Exit(1)
	}
	entries, err := decryptData(db.Data, masterPass, salt)
	if err != nil {
		fmt.Println(colorize("Invalid master password.", red))
		os.Exit(1)
	}

	switch cmd {
	case "add":
		if len(args) < 3 {
			fmt.Println(colorize("Usage: passkeeper add <name> <login> <password> [url]", yellow))
			os.Exit(1)
		}
		name, login, pwd := args[0], args[1], args[2]
		url := ""
		if len(args) > 3 {
			url = args[3]
		}
		if _, exists := entries[name]; exists {
			fmt.Println(colorize("Entry already exists. Use del first.", red))
			os.Exit(1)
		}
		entries[name] = entry{Login: login, Password: pwd, URL: url}
		encrypted, err := encryptData(entries, masterPass, salt)
		if err != nil {
			fmt.Println(colorize("Error encrypting: "+err.Error(), red))
			os.Exit(1)
		}
		db.Data = encrypted
		if err := saveDB(db); err != nil {
			fmt.Println(colorize("Error saving database: "+err.Error(), red))
			os.Exit(1)
		}
		fmt.Println(colorize("Entry '"+name+"' added.", green))

	case "get":
		if len(args) < 1 {
			fmt.Println(colorize("Usage: passkeeper get <name>", yellow))
			os.Exit(1)
		}
		name := args[0]
		entry, exists := entries[name]
		if !exists {
			fmt.Println(colorize("Entry not found.", red))
			os.Exit(1)
		}
		fmt.Printf("Login: %s\n", entry.Login)
		fmt.Printf("Password: %s\n", entry.Password)
		if entry.URL != "" {
			fmt.Printf("URL: %s\n", entry.URL)
		}

	case "list":
		if len(entries) == 0 {
			fmt.Println(colorize("No entries.", yellow))
		} else {
			for name := range entries {
				fmt.Println(name)
			}
		}

	case "del":
		if len(args) < 1 {
			fmt.Println(colorize("Usage: passkeeper del <name>", yellow))
			os.Exit(1)
		}
		name := args[0]
		if _, exists := entries[name]; !exists {
			fmt.Println(colorize("Entry not found.", red))
			os.Exit(1)
		}
		delete(entries, name)
		encrypted, err := encryptData(entries, masterPass, salt)
		if err != nil {
			fmt.Println(colorize("Error encrypting: "+err.Error(), red))
			os.Exit(1)
		}
		db.Data = encrypted
		if err := saveDB(db); err != nil {
			fmt.Println(colorize("Error saving database: "+err.Error(), red))
			os.Exit(1)
		}
		fmt.Println(colorize("Entry '"+name+"' deleted.", green))

	default:
		fmt.Println(colorize("Unknown command: "+cmd, red))
		fmt.Println("Available: master, add, get, list, del")
		os.Exit(1)
	}
}
