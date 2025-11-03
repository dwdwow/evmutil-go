package evmutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// EncryptPrivateKey encrypts an ethereum private key with password
// password: user password for encryption
// privateKeyHex: private key in bytes
// returns: encrypted data in hex encoding
func EncryptPrivateKey(password string, privateKey []byte) (string, error) {
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
	ciphertext := gcm.Seal(nil, nonce, privateKey, nil)

	// 7. Combine: salt(16) + nonce(12) + ciphertext
	encrypted := append(salt, nonce...)
	encrypted = append(encrypted, ciphertext...)

	return hex.EncodeToString(encrypted), nil
}

// DecryptPrivateKey decrypts an encrypted private key with password
// password: user password for decryption
// encryptedHex: encrypted data in hex encoding
// returns: decrypted private key in hex string format
func DecryptPrivateKey(password string, encryptedHex string) ([]byte, error) {
	// 1. Decode hex string
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}

	// 2. Minimum required: 16(salt) + 12(nonce) + 16(min ciphertext) = 44 bytes
	if len(encrypted) < 44 {
		return nil, errors.New("invalid encrypted data format")
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
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// 6. Use GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 7. Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (password may be incorrect): %w", err)
	}

	return plaintext, nil
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

	// Create password string
	password := string(passwordBytes)

	// Clear the byte slice immediately after use
	ClearBytes(passwordBytes)

	// If confirmation is required
	if confirm {
		fmt.Print("Confirm password: ")
		confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		if err != nil {
			// Clear password before returning error
			ClearString(&password)
			return "", fmt.Errorf("failed to read confirmation: %w", err)
		}

		confirmPassword := string(confirmBytes)

		// Clear the confirmation byte slice immediately
		ClearBytes(confirmBytes)

		// Check if passwords match
		if password != confirmPassword {
			ClearString(&password)
			ClearString(&confirmPassword)
			return "", errors.New("passwords do not match")
		}

		// Clear confirmation password
		ClearString(&confirmPassword)
	}

	// Validate password strength
	if len(password) < 8 {
		ClearString(&password)
		return "", errors.New("password must be at least 8 characters long")
	}

	return password, nil
}

// ClearBytes securely clears a byte slice from memory
func ClearBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// ClearString securely clears a string from memory
// This function attempts to clear the underlying memory of the string
// Note: Go's string immutability means we can't guarantee complete memory clearing
// but this is the best we can do to minimize sensitive data exposure
func ClearString(s *string) {
	if s == nil || *s == "" {
		return
	}

	// Convert to byte slice and clear each byte
	// This creates a new byte slice, so we need to work with the original string
	// by converting it to runes and back to try to clear the underlying memory
	runes := []rune(*s)
	for i := range runes {
		runes[i] = 0
	}

	// Clear the string reference
	*s = ""

	// Force garbage collection hint (though not guaranteed to run immediately)
	// This is the best we can do in Go for string memory clearing
	runtime.GC()
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
	defer ClearString(&password)

	// Step 2: Generate random private key
	fmt.Println("\nGenerating random private key...")
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get private key bytes and clear them after use
	privateKeyBytes := crypto.FromECDSA(privateKey)
	defer ClearBytes(privateKeyBytes)

	// Get Ethereum address
	address = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	fmt.Printf("Generated address: %s\n", address)

	// Step 3: Encrypt the private key
	fmt.Println("Encrypting private key...")
	encryptedKeyHex, err = EncryptPrivateKey(password, privateKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}
	fmt.Println("Encryption successful")

	// Step 4: Verify by decrypting
	fmt.Println("Verifying encryption...")
	decryptedKeyBytes, err := DecryptPrivateKey(password, encryptedKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("verification failed - cannot decrypt: %w", err)
	}
	defer ClearBytes(decryptedKeyBytes)

	// Step 5: Compare decrypted key with original
	if !bytes.Equal(decryptedKeyBytes, privateKeyBytes) {
		return "", "", errors.New("verification failed - decrypted key does not match original")
	}

	fmt.Println("✓ Verification successful - encryption is valid")

	return encryptedKeyHex, address, nil
}

// ReadEncryptedPrivateKeyFromTerminal reads an encrypted private key from terminal and decrypts it
// This function:
// 1. Prompts user to enter the encrypted private key (hex string)
// 2. Prompts user to enter the password for decryption
// 3. Decrypts the private key with the password
// 4. Returns the Ethereum private key object and the corresponding address
func ReadEncryptedPrivateKeyFromTerminal() (privateKey *ecdsa.PrivateKey, address string, err error) {
	fmt.Println("=== Decrypt Ethereum Private Key ===")

	// Step 1: Read encrypted private key from user
	fmt.Print("Enter encrypted private key: ")
	encryptedKeyBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Print newline after input

	if err != nil {
		return nil, "", fmt.Errorf("failed to read encrypted private key: %w", err)
	}

	// Clear the byte slice immediately after use
	defer ClearBytes(encryptedKeyBytes)

	// Convert to string and clean whitespace
	encryptedKeyHex := strings.TrimSpace(string(encryptedKeyBytes))
	defer ClearString(&encryptedKeyHex)

	// Validate encrypted key format
	if err := validateEncryptedKeyFormat(encryptedKeyHex); err != nil {
		return nil, "", fmt.Errorf("invalid encrypted key format: %w", err)
	}

	// Step 2: Read password from user
	password, err := ReadPasswordFromTerminal("Enter password for decryption: ", false)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read password: %w", err)
	}
	defer ClearString(&password)

	// Step 3: Decrypt the private key
	fmt.Println("Decrypting private key...")
	privateKeyBytes, err := DecryptPrivateKey(password, encryptedKeyHex)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Step 4: Parse the decrypted private key
	privateKey, err = crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse decrypted private key: %w", err)
	}

	// Get Ethereum address
	address = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	fmt.Printf("Private key decrypted successfully for address: %s\n", address)

	return privateKey, address, nil
}

// validateEncryptedKeyFormat validates the format of an encrypted private key
func validateEncryptedKeyFormat(encryptedHex string) error {
	if encryptedHex == "" {
		return errors.New("encrypted key cannot be empty")
	}

	// Remove 0x prefix if present
	hexString := strings.TrimPrefix(encryptedHex, "0x")
	hexString = strings.TrimPrefix(hexString, "0X")

	// Check if it's valid hex
	_, err := hex.DecodeString(hexString)
	if err != nil {
		return fmt.Errorf("invalid hex format: %w", err)
	}

	// Check minimum length (salt + nonce + minimum ciphertext)
	if len(hexString) < 88 { // 44 bytes minimum = 88 hex chars
		return errors.New("encrypted key too short - invalid format")
	}

	return nil
}

// PrivateKeyFromWallet extracts the private key bytes from a wallet (ECDSA private key) object
// Returns the private key as a byte slice (32 bytes)
func PrivateKeyFromWallet(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	// Extract private key bytes (32 bytes)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	return privateKeyBytes, nil
}

// PrivateKeyHexFromWallet extracts the private key from a wallet (ECDSA private key) object
// Returns the private key as a hex string (64 hex characters, without 0x prefix)
func PrivateKeyHexFromWallet(privateKey *ecdsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key cannot be nil")
	}

	// Extract private key bytes and convert to hex
	privateKeyBytes := crypto.FromECDSA(privateKey)
	return hex.EncodeToString(privateKeyBytes), nil
}

// SignMessageWithPrivateKey signs a message using a private key object
func SignMessageWithPrivateKey(privateKey *ecdsa.PrivateKey, message string) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key cannot be nil")
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
