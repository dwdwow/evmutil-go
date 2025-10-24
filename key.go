package evmutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// EncryptPrivateKey encrypts an ethereum private key with password
// password: user password for encryption
// privateKeyHex: private key in hex string format (without 0x prefix)
// returns: encrypted data in hex encoding
func EncryptPrivateKey(password string, privateKeyHex string) (string, error) {
	// 1. Generate random salt (16 bytes)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// 2. Derive key from password using PBKDF2 (100,000 iterations)
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// 3. Create AES-256 cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// 4. Use GCM mode (provides authenticated encryption)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// 5. Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 6. Encrypt private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key format: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, privateKeyBytes, nil)

	// 7. Combine: salt(16) + nonce(12) + ciphertext
	encrypted := append(salt, nonce...)
	encrypted = append(encrypted, ciphertext...)

	return hex.EncodeToString(encrypted), nil
}

// DecryptPrivateKey decrypts an encrypted private key with password
// password: user password for decryption
// encryptedHex: encrypted data in hex encoding
// returns: decrypted private key in hex string format
func DecryptPrivateKey(password string, encryptedHex string) (string, error) {
	// 1. Decode hex string
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %w", err)
	}

	// 2. Minimum required: 16(salt) + 12(nonce) + 16(min ciphertext) = 44 bytes
	if len(encrypted) < 44 {
		return "", errors.New("invalid encrypted data format")
	}

	// 3. Extract salt and nonce
	salt := encrypted[:16]
	nonce := encrypted[16:28]
	ciphertext := encrypted[28:]

	// 4. Derive key using same parameters
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// 5. Create AES-256 cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// 6. Use GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// 7. Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (password may be incorrect): %w", err)
	}

	return hex.EncodeToString(plaintext), nil
}

// SaveEncryptedKey saves encrypted key to file
func SaveEncryptedKey(filename string, encryptedHex string) error {
	return os.WriteFile(filename, []byte(encryptedHex), 0600)
}

// LoadEncryptedKey loads encrypted key from file and cleans whitespace
func LoadEncryptedKey(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	// Remove all whitespace characters (spaces, newlines, carriage returns, tabs)
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1 // Remove the character
		}
		return r
	}, string(data))
	return cleaned, nil
}

// ReadPasswordFromTerminal reads password from terminal with maximum security
// - Password input is hidden (no echo)
// - Password is cleared from memory after use
// - Supports confirmation mode for new passwords
// Returns the password and any error encountered
func ReadPasswordFromTerminal(prompt string, confirm bool) (string, error) {
	fmt.Print(prompt)

	// Read password without echoing to terminal
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Print newline after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	password := string(passwordBytes)

	// Clear the byte slice immediately
	for i := range passwordBytes {
		passwordBytes[i] = 0
	}

	// If confirmation is required
	if confirm {
		fmt.Print("Confirm password: ")
		confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		if err != nil {
			// Clear password before returning error
			clearString(&password)
			return "", fmt.Errorf("failed to read confirmation: %w", err)
		}

		confirmPassword := string(confirmBytes)

		// Clear the confirmation byte slice
		for i := range confirmBytes {
			confirmBytes[i] = 0
		}

		// Check if passwords match
		if password != confirmPassword {
			clearString(&password)
			clearString(&confirmPassword)
			return "", errors.New("passwords do not match")
		}

		// Clear confirmation password
		clearString(&confirmPassword)
	}

	// Validate password strength
	if len(password) < 8 {
		clearString(&password)
		return "", errors.New("password must be at least 8 characters long")
	}

	return password, nil
}

// clearString securely clears a string from memory
func clearString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Convert to byte slice and clear
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// GenerateAndEncryptNewKey generates a new random private key and encrypts it with user password
// This function:
// 1. Prompts user to enter and confirm a new password
// 2. Generates a random Ethereum private key
// 3. Encrypts the private key with the password
// 4. Verifies the encryption by attempting to decrypt
// 5. Returns the encrypted key in hex format and the Ethereum address
func GenerateAndEncryptNewKey() (encryptedKeyHex string, address string, err error) {
	fmt.Println("=== Generate New Encrypted Ethereum Private Key ===")

	// Step 1: Read and confirm password from user
	password, err := ReadPasswordFromTerminal("Enter password for new key: ", true)
	if err != nil {
		return "", "", fmt.Errorf("failed to read password: %w", err)
	}
	defer clearString(&password)

	// Step 2: Generate random private key
	fmt.Println("\nGenerating random private key...")
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKeyHex := hex.EncodeToString(crypto.FromECDSA(privateKey))
	defer clearString(&privateKeyHex)

	// Get Ethereum address
	address = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	fmt.Printf("Generated address: %s\n", address)

	// Step 3: Encrypt the private key
	fmt.Println("Encrypting private key...")
	encryptedKeyHex, err = EncryptPrivateKey(password, privateKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	fmt.Println("Encryption successful")

	// Step 4: Verify by decrypting
	fmt.Println("Verifying encryption...")
	decryptedKeyHex, err := DecryptPrivateKey(password, encryptedKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("verification failed - cannot decrypt: %w", err)
	}
	defer clearString(&decryptedKeyHex)

	// Step 5: Compare decrypted key with original
	if decryptedKeyHex != privateKeyHex {
		return "", "", errors.New("verification failed - decrypted key does not match original")
	}

	fmt.Println("✓ Verification successful - encryption is valid")

	return encryptedKeyHex, address, nil
}

// SignMessageWithDecryptedKey signs a message using decrypted private key
func SignMessageWithDecryptedKey(privateKeyHex string, message string) (string, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Hash message with Keccak256
	messageHash := crypto.Keccak256Hash([]byte(message))

	// Sign
	signature, err := crypto.Sign(messageHash.Bytes(), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return hex.EncodeToString(signature), nil
}
