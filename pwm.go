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
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	dataFile   = "passwords.enc"
	saltSize   = 32
	keySize    = 32
	iterations = 100000
)

var (
	// Color palette
	primaryColor   = lipgloss.Color("#7C3AED")
	secondaryColor = lipgloss.Color("#EC4899")
	successColor   = lipgloss.Color("#10B981")
	errorColor     = lipgloss.Color("#EF4444")
	mutedColor     = lipgloss.Color("#6B7280")
	accentColor    = lipgloss.Color("#3B82F6")

	// Styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			MarginBottom(1).
			Padding(0, 2)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(secondaryColor).
			MarginTop(1).
			MarginBottom(1)

	labelStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5E7EB"))

	successStyle = lipgloss.NewStyle().
			Foreground(successColor).
			Bold(true).
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(successColor)

	errorStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true).
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(errorColor)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			MarginBottom(1)

	separatorStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true)

	commandStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	usageStyle = lipgloss.NewStyle().
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(mutedColor)
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
	printBanner()

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
			fmt.Println(errorStyle.Render("❌ Error: Missing password name"))
			fmt.Println(mutedStyle.Render("Usage: password-manager get <name>"))
			os.Exit(1)
		}
		getPassword(os.Args[2])
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println(errorStyle.Render("❌ Error: Missing password name"))
			fmt.Println(mutedStyle.Render("Usage: password-manager delete <name>"))
			os.Exit(1)
		}
		deletePassword(os.Args[2])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printBanner() {
	banner := `
 ╔═══════════════════════════════════════╗
 ║   🔐 Secure Password Manager 🔐      ║
 ╚═══════════════════════════════════════╝
`
	fmt.Println(titleStyle.Render(banner))
}

func printUsage() {
	usage := usageStyle.Render(
		commandStyle.Render("Available Commands:\n\n") +
			"  " + labelStyle.Render("add") + "              Add a new password\n" +
			"  " + labelStyle.Render("list") + "             List all stored passwords\n" +
			"  " + labelStyle.Render("get <name>") + "       Retrieve a specific password\n" +
			"  " + labelStyle.Render("delete <name>") + "    Delete a password\n",
	)
	fmt.Println(usage)
}

func addPassword() {
	fmt.Println(headerStyle.Render("➕ Adding New Password"))

	var cred Credential

	fmt.Print(labelStyle.Render("Name/Identifier: "))
	fmt.Scanln(&cred.Name)

	fmt.Print(labelStyle.Render("URL: "))
	fmt.Scanln(&cred.URL)

	fmt.Print(labelStyle.Render("Username: "))
	fmt.Scanln(&cred.Username)

	fmt.Print(labelStyle.Render("Password: "))
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println(errorStyle.Render("❌ Error reading password: " + err.Error()))
		os.Exit(1)
	}
	cred.Password = string(passBytes)
	fmt.Println()

	masterPass := promptMasterPassword(labelStyle.Render("🔑 Master Password: "))

	store, err := loadStore(masterPass)
	if err != nil && !os.IsNotExist(err) {
		fmt.Println(errorStyle.Render("❌ Error loading store: " + err.Error()))
		os.Exit(1)
	}

	store.Credentials = append(store.Credentials, cred)

	if err := saveStore(store, masterPass); err != nil {
		fmt.Println(errorStyle.Render("❌ Error saving store: " + err.Error()))
		os.Exit(1)
	}

	fmt.Println(successStyle.Render("✅ Password saved successfully!"))
}

func listPasswords() {
	fmt.Println(headerStyle.Render("📋 Stored Passwords"))

	masterPass := promptMasterPassword(labelStyle.Render("🔑 Master Password: "))

	store, err := loadStore(masterPass)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(mutedStyle.Render("No passwords stored yet."))
			return
		}
		fmt.Println(errorStyle.Render("❌ Error loading store (wrong password?): " + err.Error()))
		os.Exit(1)
	}

	if len(store.Credentials) == 0 {
		fmt.Println(mutedStyle.Render("No passwords stored yet."))
		return
	}

	for i, cred := range store.Credentials {
		content := labelStyle.Render("Name: ") + valueStyle.Render(cred.Name) + "\n" +
			labelStyle.Render("URL:  ") + valueStyle.Render(cred.URL) + "\n" +
			labelStyle.Render("User: ") + valueStyle.Render(cred.Username)

		if i < len(store.Credentials)-1 {
			fmt.Println(boxStyle.Render(content))
		} else {
			fmt.Println(boxStyle.MarginBottom(0).Render(content))
		}
	}

	fmt.Println()
	fmt.Println(mutedStyle.Render(fmt.Sprintf("Total: %d password(s)", len(store.Credentials))))
}

func getPassword(name string) {
	fmt.Println(headerStyle.Render("🔍 Retrieving Password"))

	masterPass := promptMasterPassword(labelStyle.Render("🔑 Master Password: "))

	store, err := loadStore(masterPass)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(mutedStyle.Render("No passwords stored yet."))
			return
		}
		fmt.Println(errorStyle.Render("❌ Error loading store (wrong password?): " + err.Error()))
		os.Exit(1)
	}

	for _, cred := range store.Credentials {
		if cred.Name == name {
			content := labelStyle.Render("Name:     ") + valueStyle.Render(cred.Name) + "\n" +
				labelStyle.Render("URL:      ") + valueStyle.Render(cred.URL) + "\n" +
				labelStyle.Render("Username: ") + valueStyle.Render(cred.Username) + "\n" +
				labelStyle.Render("Password: ") + successStyle.Padding(0).Border(lipgloss.NormalBorder(), false).Render(cred.Password)

			fmt.Println(boxStyle.Render(content))
			return
		}
	}

	fmt.Println(errorStyle.Render(fmt.Sprintf("❌ No password found with name: %s", name)))
}

func deletePassword(name string) {
	fmt.Println(headerStyle.Render("🗑️  Deleting Password"))

	masterPass := promptMasterPassword(labelStyle.Render("🔑 Master Password: "))

	store, err := loadStore(masterPass)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(mutedStyle.Render("No passwords stored yet."))
			return
		}
		fmt.Println(errorStyle.Render("❌ Error loading store (wrong password?): " + err.Error()))
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
		fmt.Println(errorStyle.Render(fmt.Sprintf("❌ No password found with name: %s", name)))
		return
	}

	store.Credentials = newCreds
	if err := saveStore(store, masterPass); err != nil {
		fmt.Println(errorStyle.Render("❌ Error saving store: " + err.Error()))
		os.Exit(1)
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("✅ Password '%s' deleted successfully!", name)))
}

func promptMasterPassword(prompt string) string {
	fmt.Print(prompt)
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println(errorStyle.Render("\n❌ Error reading password: " + err.Error()))
		os.Exit(1)
	}
	fmt.Println()
	return string(passBytes)
}

func loadStore(masterPassword string) (*PasswordStore, error) {
	data, err := os.ReadFile(dataFile)
	if err != nil {
		if os.IsNotExist(err) {
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
