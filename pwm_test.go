package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestDeriveKey tests that key derivation produces consistent results
func TestDeriveKey(t *testing.T) {
	password := "testpassword123"
	salt := make([]byte, saltSize)
	rand.Read(salt)

	key1 := deriveKey(password, salt)
	key2 := deriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("deriveKey should produce consistent results with same inputs")
	}

	if len(key1) != keySize {
		t.Errorf("deriveKey should produce %d byte key, got %d", keySize, len(key1))
	}

	// Different password should produce different key
	key3 := deriveKey("differentpassword", salt)
	if bytes.Equal(key1, key3) {
		t.Error("deriveKey should produce different keys for different passwords")
	}

	// Different salt should produce different key
	salt2 := make([]byte, saltSize)
	rand.Read(salt2)
	key4 := deriveKey(password, salt2)
	if bytes.Equal(key1, key4) {
		t.Error("deriveKey should produce different keys for different salts")
	}
}

// TestEncryptDecrypt tests basic encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, keySize)
	rand.Read(key)

	plaintext := []byte("This is a secret message!")

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("ciphertext should not equal plaintext")
	}

	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text should equal original plaintext\nGot: %s\nWant: %s", decrypted, plaintext)
	}
}

// TestEncryptDecryptDifferentKeys tests that wrong key fails decryption
func TestEncryptDecryptDifferentKeys(t *testing.T) {
	key1 := make([]byte, keySize)
	key2 := make([]byte, keySize)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("Secret data")

	ciphertext, err := encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decrypt(ciphertext, key2)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

// TestEncryptNonDeterministic tests that encrypting same data produces different ciphertext
func TestEncryptNonDeterministic(t *testing.T) {
	key := make([]byte, keySize)
	rand.Read(key)

	plaintext := []byte("Same message")

	ciphertext1, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	ciphertext2, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("encrypting same plaintext should produce different ciphertext (different nonces)")
	}
}

// TestDecryptTamperedData tests that tampered data fails decryption
func TestDecryptTamperedData(t *testing.T) {
	key := make([]byte, keySize)
	rand.Read(key)

	plaintext := []byte("Original message")

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with the ciphertext
	if len(ciphertext) > 20 {
		ciphertext[20] ^= 0x01 // Flip one bit
	}

	_, err = decrypt(ciphertext, key)
	if err == nil {
		t.Error("decrypt should fail with tampered data")
	}
}

// TestSaveLoadStore tests saving and loading the password store
func TestSaveLoadStore(t *testing.T) {
	testFile := "test_passwords.enc"
	defer os.Remove(testFile)

	// Temporarily override dataFile
	// originalDataFile := dataFile
	// defer func() {
	// 	// This won't work since dataFile is const, but shows the intent
	// 	// In a real scenario, we'd refactor to make dataFile configurable
	// }()

	password := "testmasterpass"

	// Create a store with test data
	salt := make([]byte, saltSize)
	rand.Read(salt)

	store := &PasswordStore{
		Salt: salt,
		Credentials: []Credential{
			{
				Name:     "github",
				URL:      "https://github.com",
				Username: "testuser",
				Password: "testpass123",
			},
			{
				Name:     "gmail",
				URL:      "https://gmail.com",
				Username: "user@example.com",
				Password: "gmailpass456",
			},
		},
	}

	// Save the store (we'll use a helper that accepts filename)
	if err := saveStoreToFile(store, password, testFile); err != nil {
		t.Fatalf("saveStore failed: %v", err)
	}

	// Load the store
	loadedStore, err := loadStoreFromFile(password, testFile)
	if err != nil {
		t.Fatalf("loadStore failed: %v", err)
	}

	// Verify data
	if len(loadedStore.Credentials) != len(store.Credentials) {
		t.Errorf("loaded store has %d credentials, want %d", len(loadedStore.Credentials), len(store.Credentials))
	}

	for i, cred := range loadedStore.Credentials {
		if cred.Name != store.Credentials[i].Name {
			t.Errorf("credential %d name mismatch: got %s, want %s", i, cred.Name, store.Credentials[i].Name)
		}
		if cred.URL != store.Credentials[i].URL {
			t.Errorf("credential %d URL mismatch: got %s, want %s", i, cred.URL, store.Credentials[i].URL)
		}
		if cred.Username != store.Credentials[i].Username {
			t.Errorf("credential %d username mismatch: got %s, want %s", i, cred.Username, store.Credentials[i].Username)
		}
		if cred.Password != store.Credentials[i].Password {
			t.Errorf("credential %d password mismatch: got %s, want %s", i, cred.Password, store.Credentials[i].Password)
		}
	}
}

// TestLoadStoreWrongPassword tests that wrong password fails to load
func TestLoadStoreWrongPassword(t *testing.T) {
	testFile := "test_wrong_pass.enc"
	defer os.Remove(testFile)

	correctPassword := "correctpass"
	wrongPassword := "wrongpass"

	salt := make([]byte, saltSize)
	rand.Read(salt)

	store := &PasswordStore{
		Salt: salt,
		Credentials: []Credential{
			{Name: "test", URL: "test.com", Username: "user", Password: "pass"},
		},
	}

	if err := saveStoreToFile(store, correctPassword, testFile); err != nil {
		t.Fatalf("saveStore failed: %v", err)
	}

	_, err := loadStoreFromFile(wrongPassword, testFile)
	if err == nil {
		t.Error("loadStore should fail with wrong password")
	}
}

// TestLoadNonExistentStore tests loading when file doesn't exist
func TestLoadNonExistentStore(t *testing.T) {
	testFile := "nonexistent_file.enc"

	store, err := loadStoreFromFile("anypassword", testFile)
	if err != nil {
		t.Fatalf("loadStore should create new store when file doesn't exist, got error: %v", err)
	}

	if len(store.Credentials) != 0 {
		t.Errorf("new store should have 0 credentials, got %d", len(store.Credentials))
	}

	if len(store.Salt) != saltSize {
		t.Errorf("new store should have salt of size %d, got %d", saltSize, len(store.Salt))
	}
}

// Helper functions that accept filenames for testing
func saveStoreToFile(store *PasswordStore, masterPassword, filename string) error {
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
	return os.WriteFile(filename, output, 0600)
}

func loadStoreFromFile(masterPassword, filename string) (*PasswordStore, error) {
	data, err := os.ReadFile(filename)
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

// TestCredentialStruct tests the Credential structure
func TestCredentialStruct(t *testing.T) {
	cred := Credential{
		Name:     "test",
		URL:      "https://test.com",
		Username: "testuser",
		Password: "testpass",
	}

	if cred.Name != "test" {
		t.Errorf("Name mismatch: got %s, want test", cred.Name)
	}
	if cred.URL != "https://test.com" {
		t.Errorf("URL mismatch: got %s, want https://test.com", cred.URL)
	}
	if cred.Username != "testuser" {
		t.Errorf("Username mismatch: got %s, want testuser", cred.Username)
	}
	if cred.Password != "testpass" {
		t.Errorf("Password mismatch: got %s, want testpass", cred.Password)
	}
}

// TestEmptyStore tests operations on empty store
func TestEmptyStore(t *testing.T) {
	testFile := "test_empty.enc"
	defer os.Remove(testFile)

	password := "testpass"
	salt := make([]byte, saltSize)
	rand.Read(salt)

	store := &PasswordStore{
		Salt:        salt,
		Credentials: []Credential{},
	}

	if err := saveStoreToFile(store, password, testFile); err != nil {
		t.Fatalf("saveStore failed: %v", err)
	}

	loadedStore, err := loadStoreFromFile(password, testFile)
	if err != nil {
		t.Fatalf("loadStore failed: %v", err)
	}

	if len(loadedStore.Credentials) != 0 {
		t.Errorf("empty store should have 0 credentials, got %d", len(loadedStore.Credentials))
	}
}

// TestMultipleCredentials tests storing multiple credentials
func TestMultipleCredentials(t *testing.T) {
	testFile := "test_multiple.enc"
	defer os.Remove(testFile)

	password := "testpass"
	salt := make([]byte, saltSize)
	rand.Read(salt)

	credentials := make([]Credential, 100)
	for i := 0; i < 100; i++ {
		credentials[i] = Credential{
			Name:     string(rune('a' + i)),
			URL:      "https://example.com",
			Username: "user" + string(rune('0'+i)),
			Password: "pass" + string(rune('0'+i)),
		}
	}

	store := &PasswordStore{
		Salt:        salt,
		Credentials: credentials,
	}

	if err := saveStoreToFile(store, password, testFile); err != nil {
		t.Fatalf("saveStore failed: %v", err)
	}

	loadedStore, err := loadStoreFromFile(password, testFile)
	if err != nil {
		t.Fatalf("loadStore failed: %v", err)
	}

	if len(loadedStore.Credentials) != 100 {
		t.Errorf("loaded store should have 100 credentials, got %d", len(loadedStore.Credentials))
	}
}

// Benchmark tests
func BenchmarkDeriveKey(b *testing.B) {
	password := "benchmarkpassword"
	salt := make([]byte, saltSize)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deriveKey(password, salt)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, keySize)
	rand.Read(key)
	plaintext := []byte("This is a benchmark message for encryption testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypt(plaintext, key)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, keySize)
	rand.Read(key)
	plaintext := []byte("This is a benchmark message for decryption testing")
	ciphertext, _ := encrypt(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decrypt(ciphertext, key)
	}
}
