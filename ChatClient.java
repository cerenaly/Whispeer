import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient {
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

    // Signal E2EE keys - sadece client'da
    private KeyPair identityKeyPair;
    private KeyPair signedPreKeyPair;
    private KeyPair[] oneTimePreKeys = new KeyPair[10];
    private final Map<String, DoubleRatchetState> conversations = new HashMap<>();
    private final Map<String, String> userPublicKeys = new HashMap<>();
    private int preKeyId = 1;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private final DatagramSocket socket;
    private final InetAddress serverAddress;
    private final int serverPort;
    private boolean authenticated = false;
    private final Scanner scanner = new Scanner(System.in);
    private Key sessionKey;
    private IvParameterSpec ivSpec;
    private byte[] iv;
    private KeyPair dhKeyPair;
    private PublicKey serverDhPublicKey;
    private BigInteger clientNonce;
    private BigInteger serverNonce;

    public ChatClient(String serverIp, int serverPort) throws IOException {
        this.serverAddress = InetAddress.getByName(serverIp);
        this.serverPort = serverPort;
        this.socket = new DatagramSocket();
    }

    public void start() throws IOException {
        try {
            initDiffieHellman();
            performSharedKeyTwoWayAuthentication();
            initSignalKeys();
        } catch (Exception e) {
            System.err.println("Authentication setup failed: " + e.getMessage());
            return;
        }

        if (!authenticated) {
            System.out.println("Authentication failed. Exiting.");
            return;
        }

        authenticate();

        String encryptedGreeting = encrypt(GREETING_CMD);
        send(encryptedGreeting);

        Thread receiver = new Thread(this::receiveMessages);
        receiver.start();

        System.out.print("Enter message (or 'exit' to quit, use '@username message' for direct, 'broadcast message' for broadcast): \n");
        
        while (true) {
            System.out.print("] ");
            if (!scanner.hasNextLine()) {
                break;
            }
            String line = scanner.nextLine();
            
            if (line.equalsIgnoreCase("exit")) {
                break;
            }
            
            if (line.startsWith("broadcast ")) {
                sendSimpleBroadcast(line.substring("broadcast ".length()));
            } else if (line.startsWith("@")) {
                int spaceIndex = line.indexOf(" ");
                if (spaceIndex != -1) {
                    String recipient = line.substring(1, spaceIndex);
                    String message = line.substring(spaceIndex + 1);
                    sendDirectMessage(recipient, message);
                }
            } else {
                sendSimpleBroadcast(line);
            }
        }

        socket.close();
        System.out.println("Client exited.");
    }

    private void initDiffieHellman() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(1024);
        dhKeyPair = keyPairGen.generateKeyPair();
    }

    private void initSignalKeys() throws Exception {
        // Identity key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        identityKeyPair = keyGen.generateKeyPair();

        // Signed pre-key
        signedPreKeyPair = keyGen.generateKeyPair();

        // One-time pre-keys
        for (int i = 0; i < oneTimePreKeys.length; i++) {
            oneTimePreKeys[i] = keyGen.generateKeyPair();
        }
    }

    private void performSharedKeyTwoWayAuthentication() throws Exception {
        sendDhPublicKey();

        byte[] buffer = new byte[BUFFER_SIZE];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.setSoTimeout(5000);
        socket.receive(packet);

        String response = new String(packet.getData(), 0, packet.getLength());
        if (!response.startsWith(DH_PUBLIC_KEY_CMD)) {
            throw new IOException("Expected server's DH public key, but got: " + response);
        }

        String encodedServerPubKey = response.substring(DH_PUBLIC_KEY_CMD.length());
        byte[] serverPubKeyBytes = Base64.getDecoder().decode(encodedServerPubKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        serverDhPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyBytes));

        System.out.println("Received server's DH public key.");

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(serverDhPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        sessionKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
        iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        ivSpec = new IvParameterSpec(iv);

        System.out.println("Shared secret (AES Session Key) established.");

        String ivMessage = "IV:" + Base64.getEncoder().encodeToString(iv);
        send(ivMessage);

        clientNonce = new BigInteger(128, new SecureRandom());
        System.out.println("nonce " + clientNonce.toString(16) + " generated for client.");

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        String initialAuthMsg = DH_AUTH_CHALLENGE_CMD +
                Base64.getEncoder().encodeToString(clientNonce.toByteArray()) + ":" +
                Base64.getEncoder().encodeToString(timestamp.getBytes());

        send(encrypt(initialAuthMsg));

        packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        response = new String(packet.getData(), 0, packet.getLength());

        String decryptedResponse = decrypt(response);
        if (decryptedResponse == null || !decryptedResponse.startsWith(DH_AUTH_CHALLENGE_CMD)) {
            throw new IOException("Authentication challenge response invalid or decryption failed.");
        }

        String encodedNonces = decryptedResponse.substring(DH_AUTH_CHALLENGE_CMD.length());
        String[] nonceParts = encodedNonces.split(":");

        if (nonceParts.length != 3) {
            throw new IOException("Invalid nonce/timestamp format in challenge response.");
        }

        BigInteger receivedClientNonce = new BigInteger(Base64.getDecoder().decode(nonceParts[0]));
        serverNonce = new BigInteger(Base64.getDecoder().decode(nonceParts[1]));
        String serverTimestampStr = new String(Base64.getDecoder().decode(nonceParts[2]));

        LocalDateTime serverTimestamp;
        try {
            serverTimestamp = LocalDateTime.parse(serverTimestampStr, TIMESTAMP_FORMATTER);
        } catch (Exception e) {
            throw new IOException("Invalid server timestamp format: " + serverTimestampStr);
        }

        if (Duration.between(serverTimestamp, LocalDateTime.now()).abs().getSeconds() > 60) {
            throw new IOException("Server timestamp expired.");
        }

        if (!receivedClientNonce.equals(clientNonce)) {
            throw new IOException("Client nonce mismatch! Potential replay attack.");
        }

        System.out.println("Client nonce and server timestamp verified. Server nonce received.");

        String authResponseMsg = DH_AUTH_RESPONSE_CMD + Base64.getEncoder().encodeToString(serverNonce.toByteArray());
        send(encrypt(authResponseMsg));

        packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        response = new String(packet.getData(), 0, packet.getLength());

        if (response.startsWith(SIGNIN_OK) || response.startsWith(SIGNUP_OK)) {
            authenticated = true;
            System.out.println("Two-way authentication successful.");
        } else {
            System.out.println("Two-way authentication failed: " + response);
        }
    }

    private void sendDhPublicKey() throws IOException {
        byte[] publicKeyBytes = dhKeyPair.getPublic().getEncoded();
        String encodedPublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        send(DH_PUBLIC_KEY_CMD + encodedPublicKey);
        System.out.println("Sent client's DH public key.");
    }

    private String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            return null;
        }
    }

    private String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            return new String(original);
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
            return null;
        }
    }

    private void authenticate() throws IOException {
        while (true) {
            System.out.print("Do you want to sign up or sign in? (signup/signin): ");
            String choice = scanner.nextLine().trim();

            System.out.print("Enter username: ");
            String username = scanner.nextLine().trim();

            String password;
            Console console = System.console();
            if (console != null) {
                char[] passwordChars = console.readPassword("Enter password: ");
                password = new String(passwordChars);
            } else {
                System.out.print("Enter password (visible): ");
                password = scanner.nextLine().trim();
            }

            String credentials = username + ":" + password;
            String msg = null;

            if (choice.equalsIgnoreCase("signup")) {
                msg = SIGNUP_CMD + credentials;
            } else if (choice.equalsIgnoreCase("signin")) {
                msg = SIGNIN_CMD + credentials;
            } else {
                System.out.println("Invalid choice.");
                continue;
            }

            String encryptedFullCommand = encrypt(msg);
            send(encryptedFullCommand);

            byte[] buffer = new byte[BUFFER_SIZE];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            String response = new String(packet.getData(), 0, packet.getLength());
            String decryptedResponse = decrypt(response);

            if (decryptedResponse == null) {
                System.out.println("Authentication response decryption failed.");
                continue;
            }

            if (decryptedResponse.startsWith(SIGNUP_OK) || decryptedResponse.startsWith(SIGNIN_OK)) {
                System.out.println("Authentication successful.");
                authenticated = true;

                // Register public keys with server
                try {
                    registerPublicKeys();
                    System.out.println("Public keys registered with server.");
                } catch (Exception e) {
                    System.err.println("Error registering keys: " + e.getMessage());
                }
                break;
            } else {
                System.out.println("Authentication failed: " + decryptedResponse);
            }
        }
    }

    private void registerPublicKeys() throws Exception {
        // Create signature for signed pre-key
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
        sig.initSign(identityKeyPair.getPrivate());
        byte[] signedPreKeyBytes = signedPreKeyPair.getPublic().getEncoded();
        sig.update(signedPreKeyBytes);
        byte[] signature = sig.sign();

        // Send PUBLIC keys with signature to server
        String publicKeyBundle = Base64.getEncoder().encodeToString(identityKeyPair.getPublic().getEncoded()) + ":" +
                                Base64.getEncoder().encodeToString(signedPreKeyBytes) + ":" +
                                Base64.getEncoder().encodeToString(oneTimePreKeys[0].getPublic().getEncoded()) + ":" +
                                Base64.getEncoder().encodeToString(signature);

        String registerKeys = "REGISTER_PUBLIC_KEYS:" + publicKeyBundle;
        String encryptedRegister = encrypt(registerKeys);
        send(encryptedRegister);
        System.out.println("DEBUG: Registered public keys with signature");
    }

    private void performX3DH(String targetUser, String keyBundle) throws Exception {
        System.out.println("DEBUG: Performing X3DH with " + targetUser);
        String[] keys = keyBundle.split(":");
        if (keys.length < 4) {
            System.err.println("Invalid key bundle format - missing signature");
            return;
        }

        // Parse target user's public keys with signature
        byte[] targetIdentityKey = Base64.getDecoder().decode(keys[0]);
        byte[] targetSignedPreKey = Base64.getDecoder().decode(keys[1]);
        byte[] targetOneTimePreKey = Base64.getDecoder().decode(keys[2]);
        byte[] signature = Base64.getDecoder().decode(keys[3]);

        // Verify signed pre-key signature
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey targetIdentityPub = keyFactory.generatePublic(new X509EncodedKeySpec(targetIdentityKey));
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
        sig.initVerify(targetIdentityPub);
        sig.update(targetSignedPreKey);
        if (!sig.verify(signature)) {
            System.err.println("SECURITY ERROR: Invalid signed pre-key signature for " + targetUser);
            throw new SecurityException("Signed pre-key signature verification failed");
        }

        System.out.println("DEBUG: Signed pre-key signature verified for " + targetUser);

        // Generate ephemeral key for this session
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair ephemeralKey = keyGen.generateKeyPair();

        // X3DH calculation
        PublicKey targetSignedPub = keyFactory.generatePublic(new X509EncodedKeySpec(targetSignedPreKey));
        PublicKey targetOneTimePub = keyFactory.generatePublic(new X509EncodedKeySpec(targetOneTimePreKey));

        // X3DH calculations according to Signal specification
        // DH1 = DH(IK_A, SPK_B)
        KeyAgreement ka1 = KeyAgreement.getInstance("ECDH");
        ka1.init(identityKeyPair.getPrivate());
        ka1.doPhase(targetSignedPub, true);
        byte[] dh1 = ka1.generateSecret();

        // DH2 = DH(EK_A, IK_B)
        KeyAgreement ka2 = KeyAgreement.getInstance("ECDH");
        ka2.init(ephemeralKey.getPrivate());
        ka2.doPhase(targetIdentityPub, true);
        byte[] dh2 = ka2.generateSecret();

        // DH3 = DH(EK_A, SPK_B)
        KeyAgreement ka3 = KeyAgreement.getInstance("ECDH");
        ka3.init(ephemeralKey.getPrivate());
        ka3.doPhase(targetSignedPub, true);
        byte[] dh3 = ka3.generateSecret();

        // DH4 = DH(EK_A, OPK_B)
        KeyAgreement ka4 = KeyAgreement.getInstance("ECDH");
        ka4.init(ephemeralKey.getPrivate());
        ka4.doPhase(targetOneTimePub, true);
        byte[] dh4 = ka4.generateSecret();

        // SK = KDF(DH1 || DH2 || DH3 || DH4)
        byte[] sharedKeyMaterial = new byte[dh1.length + dh2.length + dh3.length + dh4.length];
        System.arraycopy(dh1, 0, sharedKeyMaterial, 0, dh1.length);
        System.arraycopy(dh2, 0, sharedKeyMaterial, dh1.length, dh2.length);
        System.arraycopy(dh3, 0, sharedKeyMaterial, dh1.length + dh2.length, dh3.length);
        System.arraycopy(dh4, 0, sharedKeyMaterial, dh1.length + dh2.length + dh3.length, dh4.length);

        // HKDF for key derivation
        byte[] salt = new byte[32]; // 32 bytes of zeros
        byte[] ikm = sharedKeyMaterial;
        byte[] info = "Signal_X3DH".getBytes();

        javax.crypto.Mac hmac = javax.crypto.Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = hmac.doFinal(ikm);

        hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
        hmac.update(info);
        hmac.update((byte) 1);
        byte[] okm = hmac.doFinal();

        // Derive root key and chain key from output key material
        SecretKey rootKey = new SecretKeySpec(Arrays.copyOfRange(okm, 0, 32), "AES");
        SecretKey sendingChainKey = new SecretKeySpec(Arrays.copyOfRange(okm, 32, 64), "AES");

        // Initialize Double Ratchet State
        KeyPairGenerator dhGen = KeyPairGenerator.getInstance("EC");
        dhGen.initialize(256);
        KeyPair initialDHKey = dhGen.generateKeyPair();

        DoubleRatchetState state = new DoubleRatchetState(rootKey, sendingChainKey, initialDHKey);
        conversations.put(targetUser, state);

        System.out.println("DEBUG: X3DH completed with " + targetUser + ", Double Ratchet initialized (signature verified)");
    }

    private void sendDirectMessage(String recipient, String msg) throws IOException {
        System.out.println("DEBUG: Attempting to send message to " + recipient + ": " + msg);
        try {
            if (!conversations.containsKey(recipient)) {
                System.out.println("DEBUG: No conversation with " + recipient + ", checking available keys...");
                // Check if we have public keys for this user
                if (!userPublicKeys.containsKey(recipient)) {
                    System.out.println("No keys available for " + recipient + ". User may not be registered.");
                    return;
                }

                // Perform X3DH
                String keyBundle = userPublicKeys.get(recipient);
                performX3DH(recipient, keyBundle);
                System.out.println("DEBUG: Conversation established with " + recipient);
            }

            DoubleRatchetState state = conversations.get(recipient);
            System.out.println("DEBUG: Current sending message number: " + state.sendingMessageNumber);

            // Double Ratchet: Derive message key from current sending chain
            byte[] messageKey = deriveMessageKey(state.sendingChainKey.getEncoded(), state.sendingMessageNumber);
            System.out.println("DEBUG: Message key derived for message number " + state.sendingMessageNumber);

            // Encrypt message
            String encryptedMsg = encryptWithMessageKey(msg, messageKey);
            System.out.println("DEBUG: Message encrypted");

            // Get current DH public key
            String dhPublicKey = Base64.getEncoder().encodeToString(state.dhKeyPair.getPublic().getEncoded());

            // Send Double Ratchet message
            String message = "DOUBLE_RATCHET_MESSAGE:" + recipient + ":" + dhPublicKey + ":" + state.sendingMessageNumber + ":" + encryptedMsg;

            // Update sending chain key and message number
            state.sendingChainKey = deriveNextChainKey(state.sendingChainKey.getEncoded());
            state.sendingMessageNumber++;

            System.out.println("DEBUG: Updated sending state - new message number: " + state.sendingMessageNumber);

            String encrypted = encrypt(message);
            send(encrypted);
            System.out.println("Message sent to " + recipient);
        } catch (Exception e) {
            System.err.println("Double Ratchet encryption failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // SIMPLIFIED BROADCAST: Multiple 1-to-1 messages using Double Ratchet
    private void sendSimpleBroadcast(String msg) throws IOException {
        System.out.println("DEBUG: Sending simple broadcast (multiple 1-to-1): " + msg);
        
        if (userPublicKeys.isEmpty()) {
            System.out.println("No users available for broadcast.");
            // Show message to sender even if no other users
            System.out.print("\r[BROADCAST from YOU] " + msg + "\n] ");
            return;
        }

        // First show the message to the sender immediately
        System.out.print("\r[BROADCAST from YOU] " + msg + "\n] ");

        int sentCount = 0;
        for (String username : userPublicKeys.keySet()) {
            try {
                // Ensure we have a conversation with this user
                if (!conversations.containsKey(username)) {
                    System.out.println("DEBUG: Establishing conversation with " + username + " for broadcast");
                    String keyBundle = userPublicKeys.get(username);
                    performX3DH(username, keyBundle);
                }

                // Send as regular encrypted message to each user
                sendDirectMessage(username, "[BROADCAST] " + msg);
                sentCount++;
                
                // Small delay to avoid overwhelming the server
                Thread.sleep(10);
                
            } catch (Exception e) {
                System.err.println("Failed to send broadcast to " + username + ": " + e.getMessage());
            }
        }
        
        System.out.println("Broadcast sent to " + sentCount + " users via individual encrypted channels");
    }

    private byte[] deriveMessageKey(byte[] chainKey, int messageNumber) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(chainKey, "HmacSHA256"));
            mac.update(("MESSAGEKEY" + messageNumber).getBytes());
            return Arrays.copyOf(mac.doFinal(), 32);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey deriveNextChainKey(byte[] currentChainKey) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(currentChainKey, "HmacSHA256"));
            mac.update("CHAIN_KEY_UPDATE".getBytes());
            byte[] newChainKey = mac.doFinal();
            return new SecretKeySpec(Arrays.copyOf(newChainKey, 32), "AES");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void dhRatchetStep(DoubleRatchetState state, PublicKey receivedDHPublicKey) throws Exception {
        // Generate new DH key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair newDHKeyPair = keyGen.generateKeyPair();

        // Perform DH with received public key
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(newDHKeyPair.getPrivate());
        ka.doPhase(receivedDHPublicKey, true);
        byte[] dhOutput = ka.generateSecret();

        // Update root key and derive new receiving chain key
        byte[] newRootKeyMaterial = kdf(state.rootKey.getEncoded(), dhOutput, "ROOT_KEY_UPDATE".getBytes());
        state.rootKey = new SecretKeySpec(Arrays.copyOfRange(newRootKeyMaterial, 0, 32), "AES");
        state.receivingChainKey = new SecretKeySpec(Arrays.copyOfRange(newRootKeyMaterial, 32, 64), "AES");

        // Update DH key pair and reset message numbers
        state.dhKeyPair = newDHKeyPair;
        state.receivingMessageNumber = 0;

        System.out.println("DEBUG: DH Ratchet step completed - new receiving chain established");
    }

    private byte[] kdf(byte[] key, byte[] input, byte[] info) throws Exception {
        javax.crypto.Mac hmac = javax.crypto.Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(key, "HmacSHA256"));
        hmac.update(input);
        hmac.update(info);
        return hmac.doFinal();
    }

    private String encryptWithMessageKey(String plaintext, byte[] messageKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());

        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(result);
    }

    private String decryptWithMessageKey(String ciphertext, byte[] messageKey) throws Exception {
        byte[] data = Base64.getDecoder().decode(ciphertext);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");

        byte[] iv = Arrays.copyOfRange(data, 0, 12);
        byte[] encrypted = Arrays.copyOfRange(data, 12, data.length);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted);
    }

    private void receiveMessages() {
        byte[] buffer = new byte[BUFFER_SIZE];
        while (true) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                String received = new String(packet.getData(), 0, packet.getLength());

                String decrypted = decrypt(received);
                if (decrypted != null) {
                    if (decrypted.startsWith("USER_KEY_BUNDLE:")) {
                        // Receive public key bundles from server
                        String[] parts = decrypted.split(":", 3);
                        if (parts.length >= 3) {
                            String username = parts[1];
                            String keyBundle = parts[2];
                            userPublicKeys.put(username, keyBundle);
                            System.out.println("DEBUG: Received public keys for " + username);

                            // Automatically perform X3DH with all users
                            try {
                                performX3DH(username, keyBundle);
                                System.out.print("\r[X3DH completed with " + username + "]\n] ");
                            } catch (Exception e) {
                                System.err.println("DEBUG: X3DH failed with " + username + ": " + e.getMessage());
                            }
                        }
                    } else if (decrypted.startsWith("DOUBLE_RATCHET_MESSAGE:")) {
                        System.out.println("DEBUG: Received DOUBLE_RATCHET_MESSAGE");
                        String[] parts = decrypted.split(":", 5);
                        if (parts.length >= 5) {
                            String sender = parts[1];
                            String dhPublicKeyStr = parts[2];
                            int messageNumber = Integer.parseInt(parts[3]);
                            String encryptedMsg = parts[4];

                            System.out.println("DEBUG: Double Ratchet message from " + sender + ", message number=" + messageNumber);

                            DoubleRatchetState state = conversations.get(sender);
                            if (state != null) {
                                try {
                                    // Check if we need to perform DH ratchet step
                                    byte[] receivedDHPublicKeyBytes = Base64.getDecoder().decode(dhPublicKeyStr);
                                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                                    PublicKey receivedDHPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(receivedDHPublicKeyBytes));

                                    // Compare with our stored public key to detect ratchet step
                                    if (!Arrays.equals(receivedDHPublicKeyBytes, state.lastReceivedDHPublicKey)) {
                                        System.out.println("DEBUG: DH Ratchet step needed");
                                        dhRatchetStep(state, receivedDHPublicKey);
                                        state.lastReceivedDHPublicKey = receivedDHPublicKeyBytes;
                                    }

                                    // Derive message key from receiving chain
                                    byte[] messageKey = deriveMessageKey(state.receivingChainKey.getEncoded(), messageNumber);
                                    String plaintext = decryptWithMessageKey(encryptedMsg, messageKey);

                                    // Update receiving chain key
                                    state.receivingChainKey = deriveNextChainKey(state.receivingChainKey.getEncoded());
                                    state.receivingMessageNumber = messageNumber + 1;

                                    System.out.println("DEBUG: Double Ratchet message decrypted successfully");
                                    
                                    // Check if it's a broadcast message
                                    if (plaintext.startsWith("[BROADCAST] ")) {
                                        String broadcastContent = plaintext.substring("[BROADCAST] ".length());
                                        System.out.print("\r[BROADCAST from " + sender + "] " + broadcastContent + "\n] ");
                                    } else {
                                        System.out.print("\r<from " + sender + "> " + plaintext + "\n] ");
                                    }
                                } catch (Exception e) {
                                    System.out.print("\r[Error: Double Ratchet decryption failed for message from " + sender + "]\n] ");
                                    System.err.println("DEBUG: Decryption error: " + e.getMessage());
                                    e.printStackTrace();
                                }
                            } else {
                                System.out.println("DEBUG: No conversation with " + sender + ", but should have been established at login");
                                System.out.print("\r[No conversation with " + sender + " - this shouldn't happen]\n] ");
                            }
                        }
                    } else {
                        // Regular message display (old broadcast etc.)
                        System.out.print("\r" + decrypted + "\n] ");
                    }
                } else {
                    System.out.print("\r[Error: Unable to decrypt message]\n] ");
                }
                System.out.flush();
            } catch (IOException e) {
                // Silent catch for socket operations
            } catch (Exception e) {
                System.out.print("\r[Error: " + e.getMessage() + "]\n] ");
                System.out.flush();
            }
        }
    }

    private void send(String msg) throws IOException {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, serverAddress, serverPort);
        socket.send(packet);
    }

    // Double Ratchet State Management
    private static class DoubleRatchetState {
        SecretKey rootKey;
        SecretKey sendingChainKey;
        SecretKey receivingChainKey;
        KeyPair dhKeyPair;
        int sendingMessageNumber = 0;
        int receivingMessageNumber = 0;
        byte[] lastReceivedDHPublicKey = null;
        Map<Integer, byte[]> skippedMessageKeys = new HashMap<>();

        DoubleRatchetState(SecretKey rootKey, SecretKey sendingChainKey, KeyPair dhKeyPair) {
            this.rootKey = rootKey;
            this.sendingChainKey = sendingChainKey;
            this.dhKeyPair = dhKeyPair;
            // Receiving chain key will be set after first DH ratchet step
        }
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java ChatClient <server-ip> <port>");
            return;
        }

        try {
            ChatClient client = new ChatClient(args[0], Integer.parseInt(args[1]));
            client.start();
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}