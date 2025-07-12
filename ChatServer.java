import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ChatServer {
    private static final int BUFFER_SIZE = 1024;
    private static final String SIGNUP_CMD = "SIGNUP:";
    private static final String SIGNIN_CMD = "SIGNIN:";
    private static final String DIRECT_MESSAGE_CMD = "DIRECT_MESSAGE:";
    private static final String BROADCAST_CMD = "BROADCAST:";
    private static final String GREETING_CMD = "GREETING";
    private static final String SIGNUP_OK = "SIGNUP_OK";
    private static final String SIGNIN_OK = "SIGNIN_OK";
    private static final String SIGNUP_FAIL = "SIGNUP_FAIL:";
    private static final String SIGNIN_FAIL = "SIGNIN_FAIL:";
    private static final String DH_PUBLIC_KEY_CMD = "DH_PUBKEY:";
    private static final String DH_AUTH_CHALLENGE_CMD = "DH_AUTH_CHALLENGE:";
    private static final String DH_AUTH_RESPONSE_CMD = "DH_AUTH_RESPONSE:";

    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Server sadece public key'leri tutar
    private static final Map<String, String> userPublicKeyBundles = new HashMap<>();
    private static final Map<String, String> authenticatedClients = new HashMap<>();
    private static final Map<String, Key> clientSessionKeys = new HashMap<>();
    private static final Map<String, IvParameterSpec> clientIvSpecs = new HashMap<>();
    private static final Map<String, PublicKey> clientDhPublicKeys = new HashMap<>();
    private static final Map<String, BigInteger> clientNonces = new HashMap<>();
    private static final Map<String, BigInteger> serverNonces = new HashMap<>();

    private static Connection db;
    private static final String LOG_FILE = "server.log";
    private static KeyPair dhKeyPair;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: java ChatServer <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);
        initDatabase();
        initDiffieHellman();

        DatagramSocket socket = new DatagramSocket(port);
        byte[] buffer = new byte[BUFFER_SIZE];

        log("Server listening on port " + port);

        while (true) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            String msg = new String(packet.getData(), 0, packet.getLength());
            InetAddress address = packet.getAddress();
            int clientPort = packet.getPort();
            String clientIdentifier = address.getHostAddress() + ":" + clientPort;

            if (msg.startsWith(DH_PUBLIC_KEY_CMD)) {
                handleDHPublicKey(socket, msg, clientIdentifier, address, clientPort);
            } else if (msg.startsWith("IV:")) {
                handleIV(msg, clientIdentifier);
            } else if (clientSessionKeys.containsKey(clientIdentifier)) {
                handleEncryptedMessage(socket, msg, clientIdentifier, address, clientPort);
            } else {
                log("Received message from unknown client or no session key: " + clientIdentifier + " - " + msg);
                send(socket, "ERROR: Please initiate Diffie-Hellman key exchange.", address, clientPort);
            }
        }
    }

    private static void handleDHPublicKey(DatagramSocket socket, String msg, String clientIdentifier, InetAddress address, int clientPort) throws Exception {
        String encodedClientPubKey = msg.substring(DH_PUBLIC_KEY_CMD.length());
        byte[] clientPubKeyBytes = Base64.getDecoder().decode(encodedClientPubKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey clientPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientPubKeyBytes));

        clientDhPublicKeys.put(clientIdentifier, clientPubKey);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(clientPubKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        SecretKey sessionKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        clientSessionKeys.put(clientIdentifier, sessionKey);

        log("Received client's DH public key and established shared secret with " + clientIdentifier);

        byte[] serverPubKeyBytes = dhKeyPair.getPublic().getEncoded();
        String encodedServerPubKey = Base64.getEncoder().encodeToString(serverPubKeyBytes);
        send(socket, DH_PUBLIC_KEY_CMD + encodedServerPubKey, address, clientPort);

        log("Sent server's DH public key to " + clientIdentifier);
    }

    private static void handleIV(String msg, String clientIdentifier) {
        String encodedIv = msg.substring("IV:".length());
        byte[] ivBytes = Base64.getDecoder().decode(encodedIv);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        clientIvSpecs.put(clientIdentifier, ivSpec);
        log("Received IV from " + clientIdentifier);
    }

    private static void handleEncryptedMessage(DatagramSocket socket, String msg, String clientIdentifier, InetAddress address, int clientPort) throws Exception {
        Key currentSessionKey = clientSessionKeys.get(clientIdentifier);
        IvParameterSpec currentIvSpec = clientIvSpecs.get(clientIdentifier);

        if (currentIvSpec == null) {
            log("IV not received yet for " + clientIdentifier);
            return;
        }

        String decryptedMsg = decrypt(msg, currentSessionKey, currentIvSpec);
        if (decryptedMsg == null) {
            log("Decryption failed for message from " + clientIdentifier);
            return;
        }

        // Handle different message types
        if (decryptedMsg.startsWith(DH_AUTH_CHALLENGE_CMD)) {
            handleAuthChallenge(socket, decryptedMsg, clientIdentifier, address, clientPort, currentSessionKey, currentIvSpec);
        } else if (decryptedMsg.startsWith(DH_AUTH_RESPONSE_CMD)) {
            handleAuthResponse(socket, decryptedMsg, clientIdentifier, address, clientPort);
        } else if (decryptedMsg.startsWith(SIGNUP_CMD)) {
            handleSignup(socket, decryptedMsg, clientIdentifier, address, clientPort, currentSessionKey, currentIvSpec);
        } else if (decryptedMsg.startsWith(SIGNIN_CMD)) {
            handleSignin(socket, decryptedMsg, clientIdentifier, address, clientPort, currentSessionKey, currentIvSpec);
        } else if (decryptedMsg.startsWith("REGISTER_PUBLIC_KEYS:")) {
            handleRegisterPublicKeys(socket, decryptedMsg, clientIdentifier, address, clientPort, currentSessionKey, currentIvSpec);
        } else if (decryptedMsg.startsWith("DOUBLE_RATCHET_MESSAGE:")) {
            handleDoubleRatchetMessage(socket, decryptedMsg, clientIdentifier);
        } else if (decryptedMsg.equals(GREETING_CMD)) {
            handleGreeting(clientIdentifier);
        }
        // Note: Old BROADCAST_CMD and SENDER_KEY_MESSAGE handling removed - now using simplified approach
    }

    private static void handleAuthChallenge(DatagramSocket socket, String decryptedMsg, String clientIdentifier, InetAddress address, int clientPort, Key sessionKey, IvParameterSpec ivSpec) throws Exception {
        String[] parts = decryptedMsg.substring(DH_AUTH_CHALLENGE_CMD.length()).split(":");
        if (parts.length != 2) {
            log("Invalid challenge format from " + clientIdentifier);
            return;
        }

        BigInteger clientNonce = new BigInteger(Base64.getDecoder().decode(parts[0]));
        String timestampStr = new String(Base64.getDecoder().decode(parts[1]));

        LocalDateTime clientTimestamp;
        try {
            clientTimestamp = LocalDateTime.parse(timestampStr, TIMESTAMP_FORMATTER);
        } catch (Exception e) {
            log("Invalid timestamp format from " + clientIdentifier + ": " + timestampStr);
            send(socket, encrypt(SIGNIN_FAIL + "Invalid timestamp format", sessionKey, ivSpec), address, clientPort);
            return;
        }

        if (Duration.between(clientTimestamp, LocalDateTime.now()).abs().getSeconds() > 60) {
            send(socket, encrypt(SIGNIN_FAIL + "Timestamp expired", sessionKey, ivSpec), address, clientPort);
            log("Authentication failed: Timestamp expired for " + clientIdentifier);
            return;
        }

        clientNonces.put(clientIdentifier, clientNonce);
        BigInteger serverNonce = new BigInteger(128, new SecureRandom());
        serverNonces.put(clientIdentifier, serverNonce);

        String serverTimestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        String responseNonces = Base64.getEncoder().encodeToString(clientNonce.toByteArray()) + ":" +
                Base64.getEncoder().encodeToString(serverNonce.toByteArray()) + ":" +
                Base64.getEncoder().encodeToString(serverTimestamp.getBytes());

        String encryptedResponse = encrypt(DH_AUTH_CHALLENGE_CMD + responseNonces, sessionKey, ivSpec);
        send(socket, encryptedResponse, address, clientPort);
        log("Sent authentication challenge to " + clientIdentifier);
    }

    private static void handleAuthResponse(DatagramSocket socket, String decryptedMsg, String clientIdentifier, InetAddress address, int clientPort) throws Exception {
        String encodedServerNonce = decryptedMsg.substring(DH_AUTH_RESPONSE_CMD.length());
        BigInteger receivedServerNonce = new BigInteger(Base64.getDecoder().decode(encodedServerNonce));
        BigInteger expectedServerNonce = serverNonces.get(clientIdentifier);

        if (expectedServerNonce == null || !receivedServerNonce.equals(expectedServerNonce)) {
            send(socket, SIGNIN_FAIL + "Authentication failed: Nonce mismatch.", address, clientPort);
            log("Authentication FAIL (nonce mismatch) for " + clientIdentifier);
            return;
        }

        send(socket, SIGNIN_OK, address, clientPort);
        log("Two-way authentication successful for " + clientIdentifier + ". Awaiting credentials.");
    }

    private static void handleSignup(DatagramSocket socket, String decryptedMsg, String clientIdentifier, InetAddress address, int clientPort, Key sessionKey, IvParameterSpec ivSpec) throws Exception {
        String credentials = decryptedMsg.substring(SIGNUP_CMD.length());
        String[] parts = credentials.split(":", 2);
        if (parts.length < 2) return;

        String username = parts[0];
        String password = parts[1];

        if (userExists(username)) {
            send(socket, encrypt(SIGNUP_FAIL + "Username already exists", sessionKey, ivSpec), address, clientPort);
            log("SIGNUP FAIL (exists): " + username);
        } else {
            String salt = generateSalt();
            String hash = hashPassword(password, salt);
            insertUser(username, salt, hash);
            authenticatedClients.put(clientIdentifier, username);
            send(socket, encrypt(SIGNUP_OK, sessionKey, ivSpec), address, clientPort);
            log("User signed up: " + username + " from " + clientIdentifier);
        }
    }

    private static void handleSignin(DatagramSocket socket, String decryptedMsg, String clientIdentifier, InetAddress address, int clientPort, Key sessionKey, IvParameterSpec ivSpec) throws Exception {
        String credentials = decryptedMsg.substring(SIGNIN_CMD.length());
        String[] parts = credentials.split(":", 2);
        if (parts.length < 2) return;

        String username = parts[0];
        String password = parts[1];

        String[] result = getUser(username);
        if (result != null) {
            String salt = result[0];
            String storedHash = result[1];
            String inputHash = hashPassword(password, salt);

            if (storedHash.equals(inputHash)) {
                authenticatedClients.put(clientIdentifier, username);

                // Load existing public keys from database
                try {
                    String userKeyBundle = getUserPublicKeys(username);
                    if (userKeyBundle != null) {
                        userPublicKeyBundles.put(username, userKeyBundle);
                        log("Loaded public keys for user: " + username);
                    }
                } catch (SQLException e) {
                    log("Error loading user keys: " + e.getMessage());
                }

                System.out.println("User signed in: " + username);
                send(socket, encrypt(SIGNIN_OK, sessionKey, ivSpec), address, clientPort);
                log("User signed in: " + username + " from " + clientIdentifier);

                // Send public key bundles of all other authenticated users
                sendAllUserKeyBundles(socket, clientIdentifier, username, sessionKey, ivSpec);

                // Deliver offline messages
                try {
                    deliverOfflineMessages(username, clientIdentifier, socket);
                } catch (SQLException e) {
                    log("Error delivering offline messages: " + e.getMessage());
                }
            } else {
                send(socket, encrypt(SIGNIN_FAIL + "Invalid credentials", sessionKey, ivSpec), address, clientPort);
                log("SIGNIN FAIL (wrong password): " + username);
            }
        } else {
            send(socket, encrypt(SIGNIN_FAIL + "User not found", sessionKey, ivSpec), address, clientPort);
            log("SIGNIN FAIL (no such user): " + username);
        }
    }

    private static void handleRegisterPublicKeys(DatagramSocket socket, String decryptedMsg, String clientIdentifier, InetAddress address, int clientPort, Key sessionKey, IvParameterSpec ivSpec) throws Exception {
        String keyBundle = decryptedMsg.substring("REGISTER_PUBLIC_KEYS:".length());
        String username = authenticatedClients.get(clientIdentifier);

        if (username != null) {
            // Verify signed pre-key signature before storing
            if (verifySignedPreKeySignature(keyBundle)) {
                userPublicKeyBundles.put(username, keyBundle);
                try {
                    saveUserPublicKeys(username, keyBundle);
                    log("Registered public keys for user " + username + " (signature verified)");
                    // Notify all other authenticated users about new public keys
                    notifyUsersAboutNewPublicKeys(socket, username, keyBundle);
                } catch (SQLException e) {
                    log("Error saving user public keys: " + e.getMessage());
                }
            } else {
                log("SECURITY WARNING: Invalid signed pre-key signature from " + username);
                send(socket, encrypt("ERROR: Invalid key signature", sessionKey, ivSpec), address, clientPort);
            }
        }
    }

    private static void handleDoubleRatchetMessage(DatagramSocket socket, String decryptedMsg, String clientIdentifier) {
        if (!authenticatedClients.containsKey(clientIdentifier)) {
            log("Client not authenticated: " + clientIdentifier);
            return;
        }

        String[] parts = decryptedMsg.split(":", 5);
        if (parts.length < 5) {
            log("Invalid DOUBLE_RATCHET_MESSAGE format, parts: " + parts.length);
            return;
        }

        String recipient = parts[1];
        String sender = authenticatedClients.get(clientIdentifier);
        String dhPublicKey = parts[2];  // Current DH public key
        String messageNumber = parts[3];
        String encryptedMsg = parts[4];

        // Forward message to recipient
        forwardDoubleRatchetMessage(socket, sender, recipient, dhPublicKey, messageNumber, encryptedMsg);
    }

    private static void handleGreeting(String clientIdentifier) {
        if (authenticatedClients.containsKey(clientIdentifier)) {
            String user = authenticatedClients.get(clientIdentifier);
            log("GREETING from " + user);
        }
    }

    private static void initDatabase() throws SQLException {
        db = DriverManager.getConnection("jdbc:sqlite:users.db");
        try (Statement stmt = db.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT, hash TEXT)");
            // Sadece PUBLIC key'leri sakla
            stmt.execute("CREATE TABLE IF NOT EXISTS user_public_keys (username TEXT PRIMARY KEY, public_key_bundle TEXT)");
            // Store offline messages - Double Ratchet format
            stmt.execute("CREATE TABLE IF NOT EXISTS offline_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, sender TEXT, dh_public_key TEXT, message_number TEXT, encrypted_message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
        }
    }

    private static void saveUserPublicKeys(String username, String publicKeyBundle) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("INSERT OR REPLACE INTO user_public_keys (username, public_key_bundle) VALUES (?, ?)")) {
            stmt.setString(1, username);
            stmt.setString(2, publicKeyBundle);
            stmt.executeUpdate();
        }
    }

    private static String getUserPublicKeys(String username) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("SELECT public_key_bundle FROM user_public_keys WHERE username = ?")) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("public_key_bundle");
            }
        }
        return null;
    }

    private static void sendAllUserKeyBundles(DatagramSocket socket, String clientIdentifier, String currentUser, Key sessionKey, IvParameterSpec ivSpec) {
        // Send public keys of all users (from database and currently authenticated)
        Set<String> allUsers = new HashSet<>();

        // Add all users from database
        try (Statement stmt = db.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT username FROM user_public_keys")) {
            while (rs.next()) {
                String username = rs.getString("username");
                if (!username.equals(currentUser)) {
                    allUsers.add(username);
                }
            }
        } catch (SQLException e) {
            log("Error fetching users from database: " + e.getMessage());
        }

        // Add currently authenticated users
        for (String username : userPublicKeyBundles.keySet()) {
            if (!username.equals(currentUser)) {
                allUsers.add(username);
            }
        }

        // Send key bundles
        for (String username : allUsers) {
            String keyBundle = userPublicKeyBundles.get(username);
            if (keyBundle == null) {
                try {
                    keyBundle = getUserPublicKeys(username);
                    if (keyBundle != null) {
                        userPublicKeyBundles.put(username, keyBundle);
                    }
                } catch (SQLException e) {
                    log("Error loading keys for " + username + ": " + e.getMessage());
                    continue;
                }
            }

            if (keyBundle != null) {
                String message = "USER_KEY_BUNDLE:" + username + ":" + keyBundle;
                String encrypted = encrypt(message, sessionKey, ivSpec);
                try {
                    String[] ipPort = clientIdentifier.split(":");
                    InetAddress address = InetAddress.getByName(ipPort[0]);
                    int port = Integer.parseInt(ipPort[1]);
                    send(socket, encrypted, address, port);
                    log("Sent key bundle for " + username + " to " + currentUser);
                } catch (Exception e) {
                    log("Error sending key bundle: " + e.getMessage());
                }
            }
        }
    }

    private static void notifyUsersAboutNewPublicKeys(DatagramSocket socket, String newUser, String keyBundle) {
        String message = "USER_KEY_BUNDLE:" + newUser + ":" + keyBundle;
        for (String clientId : authenticatedClients.keySet()) {
            String username = authenticatedClients.get(clientId);
            if (!username.equals(newUser)) {
                try {
                    Key sessionKey = clientSessionKeys.get(clientId);
                    IvParameterSpec ivSpec = clientIvSpecs.get(clientId);
                    String encrypted = encrypt(message, sessionKey, ivSpec);

                    String[] ipPort = clientId.split(":");
                    InetAddress address = InetAddress.getByName(ipPort[0]);
                    int port = Integer.parseInt(ipPort[1]);

                    send(socket, encrypted, address, port);
                    log("Notified " + username + " about new user " + newUser);
                } catch (Exception e) {
                    log("Error notifying user: " + e.getMessage());
                }
            }
        }
    }

    private static void forwardDoubleRatchetMessage(DatagramSocket socket, String sender, String recipient, String dhPublicKey, String messageNumber, String encryptedMsg) {
        boolean recipientFound = false;

        for (String clientId : authenticatedClients.keySet()) {
            if (authenticatedClients.get(clientId).equals(recipient)) {
                try {
                    Key sessionKey = clientSessionKeys.get(clientId);
                    IvParameterSpec ivSpec = clientIvSpecs.get(clientId);

                    String forwardedMsg = "DOUBLE_RATCHET_MESSAGE:" + sender + ":" + dhPublicKey + ":" + messageNumber + ":" + encryptedMsg;
                    String encrypted = encrypt(forwardedMsg, sessionKey, ivSpec);

                    String[] ipPort = clientId.split(":");
                    InetAddress address = InetAddress.getByName(ipPort[0]);
                    int port = Integer.parseInt(ipPort[1]);

                    send(socket, encrypted, address, port);
                    log("Forwarded double ratchet message from " + sender + " to " + recipient);
                    recipientFound = true;
                    return;
                } catch (Exception e) {
                    log("Error forwarding message: " + e.getMessage());
                }
            }
        }

        // Recipient offline ise save message
        if (!recipientFound) {
            try {
                saveOfflineMessage(recipient, sender, dhPublicKey, messageNumber, encryptedMsg);
                log("Recipient " + recipient + " offline, saved double ratchet message for later delivery");
            } catch (SQLException e) {
                log("Error saving offline message: " + e.getMessage());
            }
        }
    }

    // Offline mesaj kaydet - Double Ratchet format
    private static void saveOfflineMessage(String recipient, String sender, String dhPublicKey, String messageNumber, String encryptedMessage) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("INSERT INTO offline_messages (recipient, sender, dh_public_key, message_number, encrypted_message) VALUES (?, ?, ?, ?, ?)")) {
            stmt.setString(1, recipient);
            stmt.setString(2, sender);
            stmt.setString(3, dhPublicKey);
            stmt.setString(4, messageNumber);
            stmt.setString(5, encryptedMessage);
            stmt.executeUpdate();
            log("Saved offline double ratchet message from " + sender + " to " + recipient);
        }
    }

    // Get offline messages and delete - Double Ratchet format
    private static void deliverOfflineMessages(String username, String clientIdentifier, DatagramSocket socket) throws SQLException {
        try (PreparedStatement selectStmt = db.prepareStatement("SELECT sender, dh_public_key, message_number, encrypted_message FROM offline_messages WHERE recipient = ? ORDER BY timestamp");
             PreparedStatement deleteStmt = db.prepareStatement("DELETE FROM offline_messages WHERE recipient = ?")) {

            selectStmt.setString(1, username);
            ResultSet rs = selectStmt.executeQuery();

            while (rs.next()) {
                String sender = rs.getString("sender");
                String dhPublicKey = rs.getString("dh_public_key");
                String messageNumber = rs.getString("message_number");
                String encryptedMessage = rs.getString("encrypted_message");

                try {
                    String[] ipPort = clientIdentifier.split(":");
                    InetAddress targetIP = InetAddress.getByName(ipPort[0]);
                    int targetPort = Integer.parseInt(ipPort[1]);

                    Key targetSessionKey = clientSessionKeys.get(clientIdentifier);
                    IvParameterSpec targetIvSpec = clientIvSpecs.get(clientIdentifier);

                    String forwardedMsg = "DOUBLE_RATCHET_MESSAGE:" + sender + ":" + dhPublicKey + ":" + messageNumber + ":" + encryptedMessage;
                    String encryptedOut = encrypt(forwardedMsg, targetSessionKey, targetIvSpec);

                    send(socket, encryptedOut, targetIP, targetPort);
                    log("Delivered offline double ratchet message from " + sender + " to " + username);
                } catch (Exception e) {
                    log("Error delivering offline message: " + e.getMessage());
                }
            }

            // Delete messages
            deleteStmt.setString(1, username);
            deleteStmt.executeUpdate();
        }
    }

    private static void initDiffieHellman() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(1024);
        dhKeyPair = keyPairGen.generateKeyPair();
    }

    private static String encrypt(String plainText, Key sessionKey, IvParameterSpec ivSpec) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.err.println("Encryption failed on server: " + e.getMessage());
            return null;
        }
    }

    private static String decrypt(String encryptedText, Key sessionKey, IvParameterSpec ivSpec) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(original);
        } catch (Exception e) {
            System.err.println("Decryption failed on server: " + e.getMessage());
            return null;
        }
    }

    private static boolean userExists(String username) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("SELECT 1 FROM users WHERE username = ?")) {
            stmt.setString(1, username);
            return stmt.executeQuery().next();
        }
    }

    private static void insertUser(String username, String salt, String hash) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("INSERT INTO users (username, salt, hash) VALUES (?, ?, ?);")) {
            stmt.setString(1, username);
            stmt.setString(2, salt);
            stmt.setString(3, hash);
            stmt.executeUpdate();
        }
    }

    private static String[] getUser(String username) throws SQLException {
        try (PreparedStatement stmt = db.prepareStatement("SELECT salt, hash FROM users WHERE username = ?")) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new String[]{rs.getString("salt"), rs.getString("hash")};
            }
        }
        return null;
    }

    private static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String hashPassword(String password, String salt) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), 100000, 256);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Hashing failed", e);
        }
    }

    private static void send(DatagramSocket socket, String msg, InetAddress addr, int port) throws IOException {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
        socket.send(packet);
    }

    private static void log(String message) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String logEntry = "[" + timestamp + "] " + message;
        System.out.println(logEntry);

        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(logEntry);
        } catch (IOException e) {
            System.err.println("Failed to write to log file: " + e.getMessage());
        }
    }

    // Signed Pre-key Signature Verification
    private static boolean verifySignedPreKeySignature(String keyBundle) {
        try {
            String[] parts = keyBundle.split(":");
            if (parts.length < 4) {
                log("Invalid key bundle format for signature verification");
                return false;
            }

            // Parse key bundle: identityKey:signedPreKey:oneTimePreKey:signature
            byte[] identityKeyBytes = Base64.getDecoder().decode(parts[0]);
            byte[] signedPreKeyBytes = Base64.getDecoder().decode(parts[1]);
            byte[] signatureBytes = Base64.getDecoder().decode(parts[3]);

            // Reconstruct identity public key
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey identityPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(identityKeyBytes));

            // Verify signature
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
            sig.initVerify(identityPublicKey);
            sig.update(signedPreKeyBytes);
            boolean isValid = sig.verify(signatureBytes);

            if (isValid) {
                log("Signed pre-key signature verification: SUCCESS");
            } else {
                log("Signed pre-key signature verification: FAILED");
            }

            return isValid;
        } catch (Exception e) {
            log("Error during signature verification: " + e.getMessage());
            return false;
        }
    }
}