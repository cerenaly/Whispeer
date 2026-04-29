# 🔐 Whispeer

Whispeer is a secure, end-to-end encrypted messaging application implementing modern cryptographic protocols such as Diffie-Hellman, X3DH, and Double Ratchet.

## 🚀 Features

- 🔑 End-to-End Encryption (E2EE)
- 🔄 Perfect Forward Secrecy
- 💬 Secure direct messaging
- 📢 Encrypted broadcast messaging
- 🔐 Two-way authentication system
- 🛡️ Protection against MITM and replay attacks

## 🔐 Security Architecture

### Key Exchange
- Diffie-Hellman (1024-bit)
- AES-128 session key derivation
- Random IV generation

### Authentication
- Challenge-response mechanism
- Nonce + timestamp validation
- Replay attack protection

### Encryption
- AES-GCM for message encryption
- Unique key per message

### Signal Protocol Implementation
- X3DH Key Agreement
- Double Ratchet Algorithm
- Ephemeral key generation
- Root key rotation

## 🧠 Cryptographic Details

- PBKDF2 (100,000 iterations)
- HMAC-SHA256
- ECDH (EC-256)
- HKDF key derivation

## 🏗️ Architecture

- Client-Server architecture
- UDP-based communication
- SQLite (server-side public data only)
- In-memory secure client storage

## 📂 Features Breakdown

### 🔐 Authentication Flow
- SIGNUP / SIGNIN system
- Secure password hashing with salt

### 📢 Messaging
- Broadcast messaging system
- Encrypted communication per client

### 💬 Direct Messaging
- Signal Protocol-based secure communication
- Forward secrecy guaranteed
