# Secure Password Manager

A simple, secure command-line password manager written in Go. Store and retrieve your passwords with military-grade encryption.

## Features

- 🔒 **AES-256-GCM encryption** - Industry-standard authenticated encryption
- 🔑 **PBKDF2 key derivation** - Protection against brute force attacks (100,000 iterations)
- 🎯 **Simple CLI interface** - Easy to use from the terminal
- 📝 **Organized storage** - Store passwords with name, URL, and username
- 🛡️ **Secure file permissions** - Encrypted file is only readable by you

## Installation

1. **Clone or download** the source code

2. **Initialize Go module and install dependencies:**
```bash
go mod init pwm
go get golang.org/x/crypto/pbkdf2
go get golang.org/x/term
```

3. **Build the program:**
```bash
go build -o pwm
```

4. **(Optional) Move to your PATH:**
```bash
sudo mv pwm /usr/local/bin/
```

## Usage

### Add a new password
```bash
./pwm add
```
You'll be prompted to enter:
- Name/identifier (e.g., "github", "gmail")
- URL (e.g., "https://github.com")
- Username
- Password (hidden input)
- Master password (to encrypt the data)

### List all stored passwords
```bash
./pwm list
```
Shows names, URLs, and usernames (passwords are hidden). You'll need to enter your master password.

### Retrieve a specific password
```bash
./pwm get <name>
```
Example:
```bash
./pwm get github
```
Displays the full credential including the password.

### Delete a password
```bash
./pwm delete <name>
```
Example:
```bash
./pwm delete github
```

## Security

### What's Protected
- All passwords are encrypted using AES-256-GCM
- Your master password is never stored - it's used to derive the encryption key
- Each encryption uses a unique salt and nonce
- Data integrity is verified with authentication tags (detects tampering)

### Important Security Notes

⚠️ **Remember your master password!** There is no password recovery mechanism. If you forget it, your passwords are unrecoverable.

⚠️ **Use a strong master password!** The security of all your stored passwords depends on it. Use at least 12 characters with a mix of letters, numbers, and symbols.

⚠️ **Backup your data!** The `passwords.enc` file contains all your encrypted passwords. Keep a backup in a secure location.

⚠️ **Secure your system!** This tool cannot protect against:
- Keyloggers or malware on your computer
- Someone with physical access to your unlocked computer
- Memory dumps while the program is running

## Data Storage

All encrypted data is stored in a single file: `passwords.enc`

The file structure is:
```
[32-byte salt][encrypted data with nonce and auth tag]
```

File permissions are automatically set to `0600` (owner read/write only).

## Example Workflow

```bash
# Add your first password
./pwm add
# Enter name: github
# Enter URL: https://github.com
# Enter username: myusername
# Enter password: ********
# Enter master password: ********

# List all passwords
./pwm list
# Enter master password: ********

# Retrieve a specific password
./pwm get github
# Enter master password: ********
```

## License

This is a educational/personal project. Use at your own risk.

## Contributing

This is a simple implementation meant for learning and personal use. For production use, consider established password managers like Bitwarden, 1Password, or KeePass.