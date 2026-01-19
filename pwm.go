package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	dataFile   = "pw.enc"
	saltSize   = 32
	keySize    = 32
	iterations = 100000
)

type Credential struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type PasswordStore struct {
	Salt        []byte       `json:"salt"`
	Credentials []Credential `json:"credentials"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "add":
		addPassword()
	case "list":
		listPasswords()
	case "get":
		if len(os.Args) < 3 {
			fmt.Println("Usage: pwm get <name>")
			os.Exit(1)
		}
		getPassword(os.Args[2])
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: pwm delete <name>")
			os.Exit(1)
		}
		deletePassword(os.Args[2])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Secure Password Manager")
	fmt.Println("\nUsage:")
	fmt.Println("  pwm add                  - Add a new password")
	fmt.Println("  pwm list                 - List all stored passwords")
	fmt.Println("  pwm get <name>           - Retrieve a specific password")
	fmt.Println("  pwm delete <name>        - Delete a password")
}

func addPassword() {
	var cred Credential

	fmt.Print("Enter name/identifier: ")
	fmt.Scanln(&cred.Name)

	fmt.Print("Enter URL: ")
	fmt.Scanln(&cred.URL)

	fmt.Print("Enter username: ")
	fmt.Scanln(&cred.Username)

	fmt.Print("Enter password: ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	cred.Password = string(passBytes)
	fmt.Println()

	masterPass := promptMasterPassword("Enter master password: ")

	store, err := loadStore(masterPass)
	if err != nil && !os.IsNotExist(err) {
		fmt.Println("Error loading store:", err)
		os.Exit(1)
	}

	store.Credentials = append(store.Credentials, cred)

	if err := saveStore(store, masterPass); err != nil {
		fmt.Println("Error saving store:", err)
		os.Exit(1)
	}

	fmt.Println("Password saved successfully!")
}

func listPasswords() {
	masterPass := promptMasterPassword("Enter master password: ")

	store, err := loadStore(masterPass)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No passwords stored yet.")
			return
		}
		fmt.Println("Error loading store (wrong password?):", err)
		os.Exit(1)
	}

	if len(store.Credentials) == 0 {
		fmt.Println("No passwords stored yet.")
		return
	}

	fmt.Println("\nStored Passwords:")
	fmt.Println(strings.Repeat("-", 60))
	for _, cred := range store.Credentials {
		fmt.Printf("Name: %s\n", cred.Name)
		fmt.Printf("URL: %s\n", cred.URL)
		fmt.Printf("Username: %s\n", cred.Username)
		fmt.Println(strings.Repeat("-", 60))
	}
}

func getPassword(name string) {
	masterPass := promptMasterPassword("Enter master password: ")

	store, err := loadStore(masterPass)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No passwords stored yet.")
			return
		}
		fmt.Println("Error loading store (wrong password?):", err)
		os.Exit(1)
	}

	for _, cred := range store.Credentials {
		if cred.Name == name {
			fmt.Println("\nCredential found:")
			fmt.Printf("Name: %s\n", cred.Name)
			fmt.Printf("URL: %s\n", cred.URL)
			fmt.Printf("Username: %s\n", cred.Username)
			fmt.Printf("Password: %s\n", cred.Password)
			return
		}
	}

	fmt.Printf("No password found with name: %s\n", name)
}

func deletePassword(name string) {
	masterPass := promptMasterPassword("Enter master password: ")

	store, err := loadStore(masterPass)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No passwords stored yet.")
			return
		}
		fmt.Println("Error loading store (wrong password?):", err)
		os.Exit(1)
	}

	found := false
	newCreds := []Credential{}
	for _, cred := range store.Credentials {
		if cred.Name != name {
			newCreds = append(newCreds, cred)
		} else {
			found = true
		}
	}

	if !found {
		fmt.Printf("No password found with name: %s\n", name)
		return
	}

	store.Credentials = newCreds
	if err := saveStore(store, masterPass); err != nil {
		fmt.Println("Error saving store:", err)
		os.Exit(1)
	}

	fmt.Printf("Password '%s' deleted successfully!\n", name)
}

func promptMasterPassword(prompt string) string {
	fmt.Print(prompt)
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println()
	return string(passBytes)
}

func loadStore(masterPassword string) (*PasswordStore, error) {
	data, err := os.ReadFile(dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Create new store with random salt
			salt := make([]byte, saltSize)
			if _, err := rand.Read(salt); err != nil {
				return nil, err
			}
			return &PasswordStore{
				Salt:        salt,
				Credentials: []Credential{},
			}, nil
		}
		return nil, err
	}

	// First, decrypt to get the salt and data
	if len(data) < saltSize {
		return nil, fmt.Errorf("corrupted data file")
	}

	salt := data[:saltSize]
	encrypted := data[saltSize:]

	key := deriveKey(masterPassword, salt)
	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		return nil, err
	}

	var store PasswordStore
	if err := json.Unmarshal(decrypted, &store); err != nil {
		return nil, err
	}

	return &store, nil
}

func saveStore(store *PasswordStore, masterPassword string) error {
	data, err := json.Marshal(store)
	if err != nil {
		return err
	}

	key := deriveKey(masterPassword, store.Salt)
	encrypted, err := encrypt(data, key)
	if err != nil {
		return err
	}

	// Prepend salt to encrypted data
	output := append(store.Salt, encrypted...)

	return os.WriteFile(dataFile, output, 0600)
}

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
