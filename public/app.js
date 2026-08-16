// Base64 encoding/decoding helpers for safe binary transmission over Socket.io
function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

// --- E2EE Chat Application Client-Side Logic ---

// =======================================================
// I. UI Elements and Socket.io Initialization
// =======================================================
const socket = io();
const messageLog = document.getElementById("message-log");
const messageInput = document.getElementById("message-input");
const sendButton = document.getElementById("send-button");
const connectionStatus = document.getElementById("connection-status");
const cryptoInspectorToggle = document.getElementById("crypto-inspector-toggle");

const ROOM_ID = "myE2EEChatRoom"; // For simplicity, a fixed room ID
let localKeyPairs = null; // Stores our ECDH key pair
let peerPublicKey = null; // Stores the other peer's public key
let sharedSecret = null; // The derived AES-GCM shared secret

// Crypto Inspector toggle
cryptoInspectorToggle.addEventListener("click", () => {
    document.body.classList.toggle("crypto-inspector-active");
    cryptoInspectorToggle.classList.toggle("active");
});

// Display a message in the chat log
function displayMessage(message, type, ivBase64, ciphertextBase64) {
    const div = document.createElement("div");
    div.classList.add("message-item", type);
    div.textContent = message;

    if (document.body.classList.contains("crypto-inspector-active") && ivBase64 && ciphertextBase64) {
        const inspectorDiv = document.createElement("div");
        inspectorDiv.className = "crypto-inspector";
        inspectorDiv.innerHTML = `
            <div class="label">Ciphertext (Base64):</div>
            <div class="value">${ciphertextBase64}</div>
            <div class="label">IV:</div>
            <div class="value">${ivBase64}</div>
        `;
        div.appendChild(inspectorDiv);
    }

    messageLog.appendChild(div);
    messageLog.scrollTop = messageLog.scrollHeight;
}

// Update connection status indicator
function updateConnectionStatus(isConnected) {
    if (isConnected) {
        connectionStatus.classList.remove("disconnected");
        connectionStatus.classList.add("connected");
        connectionStatus.textContent = "Connected";
    } else {
        connectionStatus.classList.remove("connected");
        connectionStatus.classList.add("disconnected");
        connectionStatus.textContent = "Disconnected";
    }
}

socket.on("connect", async () => {
    console.log("Connected to server with ID:", socket.id);
    updateConnectionStatus(true);
    socket.emit("join-room", ROOM_ID);

    // On connection, generate keys and initiate exchange
    await generateAndExchangeKeys();
});

socket.on("disconnect", () => {
    console.log("Disconnected from server");
    updateConnectionStatus(false);
    // Clear peer-specific crypto state on disconnect
    peerPublicKey = null;
    sharedSecret = null;
});

// When another user joins the room, re-initiate key exchange
socket.on("user-joined", async (newUserId) => {
    console.log(`User ${newUserId} joined the room. Re-exchanging keys.`);
    await generateAndExchangeKeys();
});

// Handle receiving a public key from another peer
socket.on("public-key-exchange", async (data) => {
    console.log("Received public key from:", data.senderId);
    // Check if we already have a shared secret with this peer
    if (peerPublicKey && data.senderId === "theOtherPeerId") { // Simplified: assume 1:1 chat for now
        console.log("Already have a public key for this peer.");
        return;
    }

    // =======================================================
    // VI. Key Import and Shared Secret Derivation
    // =======================================================
    try {
        // Import the received public key as JWK
        peerPublicKey = await window.crypto.subtle.importKey(
            "jwk",
            data.publicKey,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            []
        );
        console.log("Peer public key imported successfully as JWK.", peerPublicKey);

        // Derive a shared secret using our private key and the peer's public key
        // Algorithm: ECDH key agreement
        // Key Derivation Function (KDF): HKDF not explicitly used by deriveKey for ECDH
        //   but the underlying cryptographic primitive performs the agreement.
        // Derived Key Algorithm: AES-GCM with 256-bit key length
        // Key Usages: encrypt and decrypt for symmetric encryption
        sharedSecret = await window.crypto.subtle.deriveKey(
            { name: "ECDH", public: peerPublicKey },
            localKeyPairs.privateKey,
            { name: "AES-GCM", length: 256 },
            true, // extractable (can be exported later if needed)
            ["encrypt", "decrypt"]
        );
        console.log("Shared secret derived successfully.", sharedSecret);
        displayMessage("Encryption session established with peer.", "system");
    } catch (err) {
        console.error(err);
        displayMessage("Error establishing secure session.", "system-error");
    }
});

// Handle receiving an encrypted chat message
socket.on("chat-message", async (data) => {
    console.log("Received encrypted message from:", data.senderId);
    if (!sharedSecret) {
        console.error("No shared secret available to decrypt message.");
        displayMessage("Received encrypted message, but no shared secret to decrypt.", "system-error");
        return;
    }

    // =======================================================
    // VII. Decryption of Chat Message
    // =======================================================
    try {
        // Convert the received Base64 strings back to Uint8Array buffers
        const ivBuffer = base64ToBuffer(data.iv);
        const ciphertextBuffer = base64ToBuffer(data.ciphertext);

        // Decrypt the ciphertext using the derived AES-GCM shared secret
        // Algorithm: AES-GCM
        // IV: Initialization Vector (must be the same as used for encryption)
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBuffer }, // IV is crucial for AES-GCM
            sharedSecret,
            ciphertextBuffer // The ciphertext as Uint8Array
        );

        // Decode the decrypted plaintext from ArrayBuffer to string
        const plaintext = new TextDecoder().decode(decryptedBuffer);
        displayMessage(`Peer: ${plaintext}`, "received");
    } catch (error) {
        console.error("Error during decryption:", error);
        displayMessage("Error decrypting message.", "system-error");
    }
});

sendButton.addEventListener("click", async () => {
    const message = messageInput.value;
    if (message.trim() === "") return;
    if (!sharedSecret) {
        displayMessage("Cannot send: No secure session established.", "system-error");
        return;
    }

    // =======================================================
    // V. Encryption of Chat Message
    // =======================================================
    try {
        // Encode the plaintext message to a Uint8Array
        const encodedMessage = new TextEncoder().encode(message);

        // Generate a random 12-byte (96-bit) Initialization Vector (IV) for AES-GCM
        // The IV MUST be unique for each encryption operation with the same key.
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Encrypt the encoded message using AES-GCM with the derived shared secret
        // Algorithm: AES-GCM
        // IV: The unique Initialization Vector generated above
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            sharedSecret,
            encodedMessage
        );

        // Convert ArrayBuffers to Base64 strings for transmission via Socket.io
        const ivBase64 = bufferToBase64(iv);
        const ciphertextBase64 = bufferToBase64(ciphertextBuffer);
    
        // Send the ciphertext and IV to the server (blind relay)
        socket.emit("chat-message", { roomId: ROOM_ID, iv: ivBase64, ciphertext: ciphertextBase64 });
        displayMessage(`You: ${message}`, "sent", ivBase64, ciphertextBase64);
        messageInput.value = "";
    } catch (error) {
        console.error("Error during encryption:", error);
        displayMessage("Error encrypting message.", "system-error");
    }
});

messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        sendButton.click();
    }
});

// =======================================================
// II. Key Generation and Exchange Functions
// =======================================================

async function generateAndExchangeKeys() {
    try {
        displayMessage("Generating new ECDH key pair...", "system");
        // =======================================================
        // III. Key Pair Generation
        // =======================================================
        // Generate an Elliptic Curve Diffie-Hellman (ECDH) key pair.
        // Curve: P-256 (a NIST standard elliptic curve)
        // Key Usages: deriveKey for the private key (to derive a shared secret)
        //             (no specific usages for the public key during generation, it's exported)
        localKeyPairs = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true, // extractable (can be exported for exchange)
            ["deriveKey"] // private key can be used to derive other keys
        );
        console.log("ECDH Key pair generated:", localKeyPairs);
        displayMessage("ECDH key pair generated.", "system");

        // =======================================================
        // IV. Public Key Export and Exchange
        // =======================================================
        // Export the public key as JWK (JSON Web Key)
        // JWK is a JSON object that can be safely transmitted over WebSockets
        const publicKeyJwk = await window.crypto.subtle.exportKey(
            "jwk",
            localKeyPairs.publicKey
        );
        console.log("Public key exported as JWK:", publicKeyJwk);

        // Send the public key JWK to the server for relay to other peers
        socket.emit("public-key-exchange", { roomId: ROOM_ID, publicKey: publicKeyJwk });
        displayMessage("Public key sent for exchange.", "system");
    } catch (err) {
        console.error(err);
        displayMessage("Error generating or exchanging keys.", "system-error");
    }
}
