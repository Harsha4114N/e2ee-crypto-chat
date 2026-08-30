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

const STORAGE_KEYS = {
    userSession: 'e2ee_chat_user_session',
    historyPrefix: 'chatHistory_'
};

const loginScreen = document.getElementById('login-screen');
const lobbyScreen = document.getElementById('lobby-screen');
const chatScreen = document.getElementById('chat-screen');

const usernameInput = document.getElementById('username-input');
const joinButton = document.getElementById('join-button');
const logoutButton = document.getElementById('logout-button');
const activeUsersList = document.getElementById('active-users-list');
const activeUserBadge = document.getElementById('active-user-badge');

const messageLog = document.getElementById('message-log');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const clearChatButton = document.getElementById('clear-chat-button');
const connectionStatus = document.getElementById('connection-status');
const chatPartner = document.getElementById('chat-partner');
const fingerprintBadge = document.getElementById('fingerprint-badge');
const securityToggle = document.getElementById('security-toggle');
const hackerToggle = document.getElementById('hacker-toggle');
const mathToggle = document.getElementById('math-toggle');
const backToLobbyButton = document.getElementById('back-to-lobby');
const wireSnifferOutput = document.getElementById('wire-sniffer-output');
const toast = document.getElementById('demo-toast');

const state = {
    activeUsers: [],
    localUsername: '',
    localKeyPair: null,
    localPublicJwk: null,
    peerSessions: new Map(),
    currentPeerId: null,
    currentPeerUsername: '',
    currentFingerprint: '',
    securityEnabled: true,
    hackerEnabled: false,
    mathVisible: false,
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

function sanitizeHistoryKey(peerName) {
    return String(peerName || 'peer')
        .trim()
        .replace(/[^a-zA-Z0-9_-]/g, '_');
}

function getHistoryStorageKey(peerName) {
    return `${STORAGE_KEYS.historyPrefix}${sanitizeHistoryKey(peerName)}`;
}

function loadStoredUserSession() {
    try {
        const raw = localStorage.getItem(STORAGE_KEYS.userSession);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        if (!parsed || !parsed.username || !parsed.publicKeyJwk || !parsed.privateKeyJwk) {
            return null;
        }
        return parsed;
    } catch (error) {
        console.error('Failed to read saved user session:', error);
        return null;
    }
}

function persistStoredUserSession(username, publicKeyJwk, privateKeyJwk) {
    localStorage.setItem(STORAGE_KEYS.userSession, JSON.stringify({ username, publicKeyJwk, privateKeyJwk }));
}

function clearStoredUserSession() {
    localStorage.removeItem(STORAGE_KEYS.userSession);
}

function loadStoredHistory(peerName) {
    try {
        const saved = localStorage.getItem(getHistoryStorageKey(peerName));
        return saved ? JSON.parse(saved) : [];
    } catch (error) {
        console.error('Failed to read saved chat history:', error);
        return [];
    }
}

function appendMessageToHistory(peerName, message, direction, ivBase64 = null, ciphertextBase64 = null) {
    if (!peerName) {
        return;
    }

    const key = getHistoryStorageKey(peerName);
    const history = loadStoredHistory(peerName);
    history.push({ message, direction, iv: ivBase64, ciphertext: ciphertextBase64 });
    localStorage.setItem(key, JSON.stringify(history));
}

function clearPeerHistory(peerName) {
    if (!peerName) {
        return;
    }
    localStorage.removeItem(getHistoryStorageKey(peerName));
}

function renderHistoryForPeer(peerName) {
    if (!peerName) {
        messageLog.innerHTML = '';
        return;
    }

    messageLog.innerHTML = '';
    const history = loadStoredHistory(peerName);
    history.forEach((entry) => {
        displayMessage(entry.message, entry.direction === 'sent' ? 'sent' : 'received', entry.iv, entry.ciphertext);
    });
}

async function restoreKeyPairFromStorage(userSession) {
    if (!userSession) {
        return null;
    }

    try {
        const privateKey = await crypto.subtle.importKey(
            'jwk',
            userSession.privateKeyJwk,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey']
        );

        const publicKey = await crypto.subtle.importKey(
            'jwk',
            userSession.publicKeyJwk,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );

        return { privateKey, publicKey };
    } catch (error) {
        console.error('Failed to restore local key pair:', error);
        return null;
    }
}

async function autoLoginFromStorage() {
    const userSession = loadStoredUserSession();
    if (!userSession) {
        return false;
    }

    try {
        const restoredKeyPair = await restoreKeyPairFromStorage(userSession);
        if (!restoredKeyPair) {
            clearStoredUserSession();
            return false;
        }

        state.localUsername = userSession.username;
        state.localKeyPair = restoredKeyPair;
        state.localPublicJwk = userSession.publicKeyJwk;
        activeUserBadge.textContent = `You: ${userSession.username}`;
        showScreen('lobby');
        displayMessage(`Welcome back, ${userSession.username}.`, 'system');
        return true;
    } catch (error) {
        console.error('Auto-login failed:', error);
        clearStoredUserSession();
        return false;
    }
}

function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(showToast.timeoutId);
    showToast.timeoutId = window.setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function displayMessage(message, type, ivBase64 = null, ciphertextBase64 = null) {
    const div = document.createElement('div');
    div.classList.add('message-item', type);

    if (type === 'sent-plaintext' || type === 'received-plaintext') {
        div.classList.add('plaintext-warning');
    }

    const textNode = document.createElement('div');
    textNode.className = 'message-text';
    textNode.textContent = message;
    div.appendChild(textNode);

    if (state.mathVisible && (ivBase64 || ciphertextBase64)) {
        const inspectorDiv = document.createElement('div');
        inspectorDiv.className = 'crypto-inspector';
        const flowLabel = type === 'sent' || type === 'sent-plaintext' ? 'Encryption pipeline' : 'Decryption pipeline';
        const leftTerm = type === 'sent' || type === 'sent-plaintext' ? 'Plaintext' : 'Ciphertext';
        const rightTerm = type === 'sent' || type === 'sent-plaintext' ? 'Ciphertext' : 'Plaintext';

        inspectorDiv.innerHTML = `
            <div class="crypto-pipeline-title">${flowLabel}</div>
            <div class="crypto-pipeline">
                <span class="flow-term">${leftTerm}</span>
                <span class="flow-arrow">→</span>
                <span class="flow-box">[AES-GCM + IV + Shared Secret]</span>
                <span class="flow-arrow">→</span>
                <span class="flow-term">${rightTerm}</span>
            </div>
            <div class="crypto-meta">
                <span><strong>IV:</strong> ${ivBase64 || 'n/a'}</span>
                <span><strong>Ciphertext:</strong> ${ciphertextBase64 || 'n/a'}</span>
            </div>
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

function updateSecurityToggle() {
    securityToggle.classList.toggle('active', state.securityEnabled);
    securityToggle.classList.toggle('inactive', !state.securityEnabled);
    securityToggle.textContent = `E2EE Protocol: ${state.securityEnabled ? 'Enabled' : 'Disabled'}`;
}

function updateHackerToggle() {
    hackerToggle.classList.toggle('active', state.hackerEnabled);
    hackerToggle.classList.toggle('inactive', !state.hackerEnabled);
    hackerToggle.textContent = `Simulate MITM Interception${state.hackerEnabled ? ': ON' : ': OFF'}`;
}

function updateMathToggle() {
    mathToggle.classList.toggle('active', state.mathVisible);
    mathToggle.classList.toggle('inactive', !state.mathVisible);
    mathToggle.textContent = `Cryptographic Pipeline Visualizer${state.mathVisible ? ': ON' : ': OFF'}`;
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
        ciphertext: packet.ciphertext,
        message: packet.message,
        isPlaintext: packet.isPlaintext
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
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

        state.localKeyPair = keyPair;
        state.localPublicJwk = publicKeyJwk;
        state.localUsername = username;
        activeUserBadge.textContent = `You: ${username}`;

        persistStoredUserSession(username, publicKeyJwk, privateKeyJwk);
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
        renderHistoryForPeer(peer.username);
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
    renderHistoryForPeer(peer.username);
    displayMessage(`Secure session established with ${peer.username}.`, 'system');
}

async function handleIncomingMessage(data) {
    const { senderId, ciphertext, iv, isPlaintext, message } = data;

    if (isPlaintext && message) {
        const renderedMessage = `${state.activeUsers.find((user) => user.id === senderId)?.username || 'Peer'}: ${message}`;
        displayMessage(renderedMessage, 'received-plaintext', null, null);
        appendMessageToHistory(state.currentPeerUsername || (state.activeUsers.find((user) => user.id === senderId)?.username || 'peer'), renderedMessage, 'received-plaintext', null, null);
        return;
    }

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
        const renderedMessage = `${session.username}: ${plaintext}`;
        displayMessage(renderedMessage, 'received', iv, ciphertext);
        appendMessageToHistory(session.username, renderedMessage, 'received', iv, ciphertext);
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

logoutButton.addEventListener('click', () => {
    clearStoredUserSession();
    state.localUsername = '';
    state.localKeyPair = null;
    state.localPublicJwk = null;
    state.peerSessions.clear();
    state.currentPeerId = null;
    state.currentPeerUsername = '';
    updateChatHeader();
    window.location.reload();
});

sendButton.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    if (!message) return;

    if (!state.currentPeerId) {
        displayMessage('Select a peer from the lobby before sending a message.', 'system-error');
        return;
    }

    const peerName = state.currentPeerUsername || 'peer';

    if (!state.securityEnabled) {
        const payload = {
            senderId: socket.id,
            recipientId: state.currentPeerId,
            isPlaintext: true,
            message
        };

        logWirePacket({ senderId: socket.id, message, isPlaintext: true }, 'OUTBOUND');
        socket.emit('private-message', payload);

        const renderedMessage = `You: ${message}`;
        displayMessage(renderedMessage, 'sent-plaintext', null, null);
        appendMessageToHistory(peerName, renderedMessage, 'sent-plaintext', null, null);
        messageInput.value = '';
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

        if (state.hackerEnabled) {
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

        const renderedMessage = `You: ${message}`;
        displayMessage(renderedMessage, 'sent', ivBase64, ciphertextBase64);
        appendMessageToHistory(peerName, renderedMessage, 'sent', ivBase64, ciphertextBase64);
        messageInput.value = '';
    } catch (error) {
        console.error('Encryption failed:', error);
        displayMessage('Unable to encrypt this message.', 'system-error');
    }
});

clearChatButton.addEventListener('click', () => {
    if (!state.currentPeerUsername) {
        displayMessage('No active peer to clear.', 'system-error');
        return;
    }

    clearPeerHistory(state.currentPeerUsername);
    messageLog.innerHTML = '';
    displayMessage(`Chat history cleared for ${state.currentPeerUsername}.`, 'system');
});

messageInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        sendButton.click();
    }
});

securityToggle.addEventListener('click', () => {
    state.securityEnabled = !state.securityEnabled;
    updateSecurityToggle();
    showToast(state.securityEnabled ? 'E2EE Enabled: AES-GCM authenticated encryption active.' : 'E2EE Disabled: Transmitting insecure plaintext over the network.');
});

hackerToggle.addEventListener('click', () => {
    state.hackerEnabled = !state.hackerEnabled;
    updateHackerToggle();
    showToast(state.hackerEnabled ? 'MITM Simulation Active: Injecting bit-flip errors during transit.' : 'MITM Simulation Inactive: Transit integrity remains unmodified.');
});

mathToggle.addEventListener('click', () => {
    state.mathVisible = !state.mathVisible;
    updateMathToggle();
    showToast(state.mathVisible ? 'Visualizer Active: Displaying cryptographic transformations.' : 'Visualizer Inactive: Cryptographic transformations are hidden.');

    if (state.currentPeerUsername) {
        renderHistoryForPeer(state.currentPeerUsername);
    }
});

backToLobbyButton.addEventListener('click', () => {
    showScreen('lobby');
    state.peerSessions.clear();
    state.currentPeerId = null;
    state.currentPeerUsername = '';
    updateChatHeader();
    messageLog.innerHTML = '';
});

socket.on('connect', async () => {
    updateConnectionStatus(true);
    console.log('Connected to server with ID:', socket.id);

    if (state.localUsername && state.localKeyPair && state.localPublicJwk) {
        socket.emit('register-user', { username: state.localUsername, publicKey: state.localPublicJwk });
    } else {
        const restored = await autoLoginFromStorage();
        if (restored && state.localUsername && state.localPublicJwk) {
            socket.emit('register-user', { username: state.localUsername, publicKey: state.localPublicJwk });
        }
    }
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
        state.peerSessions.clear();
        updateChatHeader();
        showScreen('lobby');
        displayMessage('Peer left the lobby. Please choose another user.', 'system');
    }
});

socket.on('private-message', async (data) => {
    if (data && data.senderId) {
        if (data.isPlaintext) {
            logWirePacket({ senderId: data.senderId, message: data.message, isPlaintext: true }, 'INBOUND');
        } else if (data.iv && data.ciphertext) {
            logWirePacket({ senderId: data.senderId, iv: data.iv, ciphertext: data.ciphertext }, 'INBOUND');
        }
    }
    await handleIncomingMessage(data);
});

showScreen('login');
updateConnectionStatus(false);
updateSecurityToggle();
updateHackerToggle();
updateMathToggle();
updateChatHeader();
renderLobby();

(async () => {
    const restored = await autoLoginFromStorage();
    if (!restored) {
        showScreen('login');
    }
})();
