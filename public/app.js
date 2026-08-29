// Base64 helpers for safe binary transport across Socket.io
function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function tamperCiphertext(base64Ciphertext) {
    const bytes = new Uint8Array(base64ToBuffer(base64Ciphertext));
    if (bytes.length > 0) {
        bytes[0] ^= 0xff;
    }
    return bufferToBase64(bytes);
}

const socket = io();

const loginScreen = document.getElementById('login-screen');
const lobbyScreen = document.getElementById('lobby-screen');
const chatScreen = document.getElementById('chat-screen');

const usernameInput = document.getElementById('username-input');
const joinButton = document.getElementById('join-button');
const activeUsersList = document.getElementById('active-users-list');
const activeUserBadge = document.getElementById('active-user-badge');

const messageLog = document.getElementById('message-log');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const connectionStatus = document.getElementById('connection-status');
const chatPartner = document.getElementById('chat-partner');
const fingerprintBadge = document.getElementById('fingerprint-badge');
const cryptoInspectorToggle = document.getElementById('crypto-inspector-toggle');
const mitmToggle = document.getElementById('mitm-toggle');
const backToLobbyButton = document.getElementById('back-to-lobby');
const wireSnifferOutput = document.getElementById('wire-sniffer-output');

const state = {
    activeUsers: [],
    localUsername: '',
    localKeyPair: null,
    localPublicJwk: null,
    peerSessions: new Map(),
    currentPeerId: null,
    currentPeerUsername: '',
    currentFingerprint: '',
    mitmEnabled: false,
    cryptoInspectorVisible: false,
    wireTrace: []
};

function showScreen(screenName) {
    const screens = {
        login: loginScreen,
        lobby: lobbyScreen,
        chat: chatScreen
    };

    Object.entries(screens).forEach(([name, screen]) => {
        screen.classList.toggle('active', name === screenName);
        screen.classList.toggle('hidden', name !== screenName);
    });
}

function displayMessage(message, type, ivBase64 = null, ciphertextBase64 = null) {
    const div = document.createElement('div');
    div.classList.add('message-item', type);
    div.textContent = message;

    if (state.cryptoInspectorVisible && ivBase64 && ciphertextBase64) {
        const inspectorDiv = document.createElement('div');
        inspectorDiv.className = 'crypto-inspector';
        inspectorDiv.innerHTML = `
            <span class="label">Ciphertext (Base64):</span>
            <span class="value">${ciphertextBase64}</span>
            <span class="label">IV:</span>
            <span class="value">${ivBase64}</span>
        `;
        div.appendChild(inspectorDiv);
    }

    messageLog.appendChild(div);
    messageLog.scrollTop = messageLog.scrollHeight;
}

function updateConnectionStatus(isConnected) {
    if (isConnected) {
        connectionStatus.classList.remove('disconnected');
        connectionStatus.classList.add('connected');
        connectionStatus.textContent = 'Connected';
    } else {
        connectionStatus.classList.remove('connected');
        connectionStatus.classList.add('disconnected');
        connectionStatus.textContent = 'Disconnected';
    }
}

function updateMitmToggle() {
    mitmToggle.classList.toggle('active', state.mitmEnabled);
    mitmToggle.textContent = `MITM: ${state.mitmEnabled ? 'On' : 'Off'}`;
}

function updateInspectorToggle() {
    cryptoInspectorToggle.classList.toggle('active', state.cryptoInspectorVisible);
    cryptoInspectorToggle.textContent = state.cryptoInspectorVisible ? 'Hide Crypto Inspector' : 'Toggle Crypto Inspector';
}

function renderLobby() {
    const peers = state.activeUsers.filter((user) => user.id !== socket.id);

    if (peers.length === 0) {
        activeUsersList.innerHTML = '<div class="user-card"><div><h3>No peers online</h3><span>Invite someone to join the PKI chat.</span></div></div>';
        return;
    }

    activeUsersList.innerHTML = '';

    peers.forEach((user) => {
        const card = document.createElement('div');
        card.className = 'user-card';
        card.innerHTML = `
            <div>
                <h3>${user.username}</h3>
                <span>Public key ready</span>
            </div>
            <button class="user-action-btn" data-peer-id="${user.id}" data-peer-name="${user.username}">Start Secure Chat</button>
        `;
        activeUsersList.appendChild(card);
    });

    activeUsersList.querySelectorAll('.user-action-btn').forEach((button) => {
        button.addEventListener('click', () => {
            startSecureChat(button.dataset.peerId, button.dataset.peerName);
        });
    });
}

function updateChatHeader() {
    if (state.currentPeerId) {
        chatPartner.textContent = `Secure chat with ${state.currentPeerUsername}`;
        fingerprintBadge.textContent = state.currentFingerprint ? `Fingerprint: ${state.currentFingerprint}` : 'Fingerprint: pending';
        fingerprintBadge.classList.remove('hidden');
    } else {
        chatPartner.textContent = 'No secure session';
        fingerprintBadge.textContent = 'Fingerprint: --';
        fingerprintBadge.classList.add('hidden');
    }
}

async function computeSafetyFingerprint(localPublicKey, peerPublicKey) {
    if (!localPublicKey || !peerPublicKey) {
        return '';
    }

    const hashInput = [
        JSON.stringify(localPublicKey),
        JSON.stringify(peerPublicKey)
    ].sort().join('|');

    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(hashInput));
    const hex = Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();

    const short = hex.slice(0, 6);
    return short.length > 3 ? `${short.slice(0, 3)}-${short.slice(3)}` : short;
}

function logWirePacket(packet, direction = 'OUTBOUND') {
    const raw = {
        senderId: packet.senderId,
        iv: packet.iv,
        ciphertext: packet.ciphertext
    };

    state.wireTrace.unshift({ direction, packet: raw });
    state.wireTrace = state.wireTrace.slice(0, 6);

    wireSnifferOutput.textContent = state.wireTrace
        .map((entry) => `${entry.direction}\n${JSON.stringify(entry.packet, null, 2)}`)
        .join('\n\n');
}

async function registerUser(username) {
    if (!window.crypto || !window.crypto.subtle) {
        displayMessage('Web Crypto is not supported in this browser.', 'system-error');
        return;
    }

    try {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey']
        );

        const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        state.localKeyPair = keyPair;
        state.localPublicJwk = publicKeyJwk;
        state.localUsername = username;
        activeUserBadge.textContent = `You: ${username}`;

        socket.emit('register-user', { username, publicKey: publicKeyJwk });
        showScreen('lobby');
        displayMessage('Joined the PKI lobby.', 'system');
    } catch (error) {
        console.error('Key generation failed:', error);
        displayMessage('Unable to generate keys for secure chat.', 'system-error');
    }
}

async function deriveSessionWithPeer(peerId) {
    if (state.peerSessions.has(peerId)) {
        return state.peerSessions.get(peerId);
    }

    const peer = state.activeUsers.find((user) => user.id === peerId);
    if (!peer || !state.localKeyPair) {
        return null;
    }

    try {
        const peerPublicKey = await crypto.subtle.importKey(
            'jwk',
            peer.publicKey,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );

        const sharedSecret = await crypto.subtle.deriveKey(
            { name: 'ECDH', public: peerPublicKey },
            state.localKeyPair.privateKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        const session = {
            username: peer.username,
            sharedSecret,
            publicKey: peerPublicKey
        };

        state.peerSessions.set(peerId, session);
        state.currentPeerId = peerId;
        state.currentPeerUsername = peer.username;
        state.currentFingerprint = await computeSafetyFingerprint(state.localPublicJwk, peer.publicKey);
        showScreen('chat');
        updateChatHeader();
        displayMessage(`Secure session established automatically with ${peer.username}.`, 'system');
        return session;
    } catch (error) {
        console.error('Session derivation failed:', error);
        return null;
    }
}

async function startSecureChat(peerId, peerName) {
    const peer = state.activeUsers.find((user) => user.id === peerId);
    if (!peer || !state.localKeyPair) {
        return;
    }

    const session = await deriveSessionWithPeer(peerId);
    if (!session) {
        displayMessage('Failed to establish a secure session with this peer.', 'system-error');
        return;
    }

    messageInput.focus();
    displayMessage(`Secure session established with ${peer.username}.`, 'system');
}

async function handleIncomingMessage(data) {
    const { senderId, ciphertext, iv } = data;
    let session = state.peerSessions.get(senderId);

    if (!session) {
        session = await deriveSessionWithPeer(senderId);
        if (!session) {
            displayMessage('Received encrypted data from an untrusted peer.', 'system-error');
            return;
        }
    }

    try {
        const ivBuffer = base64ToBuffer(iv);
        const ciphertextBuffer = base64ToBuffer(ciphertext);
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            session.sharedSecret,
            ciphertextBuffer
        );

        const plaintext = new TextDecoder().decode(decryptedBuffer);
        displayMessage(`${session.username}: ${plaintext}`, 'received');
    } catch (error) {
        console.error('Decryption failed:', error);
        displayMessage('Failed to decrypt incoming message.', 'system-error');
    }
}

joinButton.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
        alert('Please enter a username.');
        return;
    }

    await registerUser(username);
    usernameInput.value = '';
});

sendButton.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    if (!message) return;

    if (!state.currentPeerId) {
        displayMessage('Select a peer from the lobby before sending a message.', 'system-error');
        return;
    }

    const session = state.peerSessions.get(state.currentPeerId);
    if (!session) {
        displayMessage('No secure session is active for this peer.', 'system-error');
        return;
    }

    try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedMessage = new TextEncoder().encode(message);
        const ciphertextBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            session.sharedSecret,
            encodedMessage
        );

        const ivBase64 = bufferToBase64(iv);
        let ciphertextBase64 = bufferToBase64(ciphertextBuffer);

        if (state.mitmEnabled) {
            ciphertextBase64 = tamperCiphertext(ciphertextBase64);
        }

        const payload = {
            senderId: socket.id,
            iv: ivBase64,
            ciphertext: ciphertextBase64
        };

        logWirePacket(payload, 'OUTBOUND');

        socket.emit('private-message', {
            recipientId: state.currentPeerId,
            senderId: socket.id,
            iv: ivBase64,
            ciphertext: ciphertextBase64
        });

        displayMessage(`You: ${message}`, 'sent', ivBase64, ciphertextBase64);
        messageInput.value = '';
    } catch (error) {
        console.error('Encryption failed:', error);
        displayMessage('Unable to encrypt this message.', 'system-error');
    }
});

messageInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        sendButton.click();
    }
});

cryptoInspectorToggle.addEventListener('click', () => {
    state.cryptoInspectorVisible = !state.cryptoInspectorVisible;
    updateInspectorToggle();
});

mitmToggle.addEventListener('click', () => {
    state.mitmEnabled = !state.mitmEnabled;
    updateMitmToggle();
});

backToLobbyButton.addEventListener('click', () => {
    showScreen('lobby');
});

socket.on('connect', () => {
    updateConnectionStatus(true);
    console.log('Connected to server with ID:', socket.id);
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
    state.peerSessions.clear();
    state.currentPeerId = null;
    state.currentPeerUsername = '';
    updateChatHeader();
    displayMessage('Connection lost. Please rejoin the lobby.', 'system-error');
});

socket.on('active-users', (users) => {
    state.activeUsers = users;
    renderLobby();

    if (state.currentPeerId && !users.some((user) => user.id === state.currentPeerId)) {
        state.currentPeerId = null;
        state.currentPeerUsername = '';
        state.peerSessions.delete(state.currentPeerId);
        updateChatHeader();
        showScreen('lobby');
        displayMessage('Peer left the lobby. Please choose another user.', 'system');
    }
});

socket.on('private-message', async (data) => {
    if (data && data.senderId && data.iv && data.ciphertext) {
        logWirePacket({ senderId: data.senderId, iv: data.iv, ciphertext: data.ciphertext }, 'INBOUND');
    }
    await handleIncomingMessage(data);
});

showScreen('login');
updateConnectionStatus(false);
updateMitmToggle();
updateInspectorToggle();
updateChatHeader();
renderLobby();
