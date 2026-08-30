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
    userSession: 'securetalk_user_session',
    historyPrefix: 'securetalk_history_'
};

const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const usernameInput = document.getElementById('username-input');
const joinButton = document.getElementById('join-button');
const welcomeBackButton = document.getElementById('welcome-back-button');
const differentUserButton = document.getElementById('different-user-button');
const savedUserPanel = document.getElementById('saved-user-panel');
const newUserForm = document.getElementById('new-user-form');
const savedUsernameLabel = document.getElementById('saved-username-label');

const activeUsersList = document.getElementById('active-users-list');
const activeUserBadge = document.getElementById('active-user-badge');
const messageLog = document.getElementById('message-log');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const connectionStatus = document.getElementById('connection-status');
const chatPartner = document.getElementById('chat-partner');
const securityToggle = document.getElementById('security-toggle');
const hackerToggle = document.getElementById('hacker-toggle');
const clearChatButton = document.getElementById('clear-chat-button');
const logoutButton = document.getElementById('logout-button');
const explanationCard = document.getElementById('explanation-card');
const keyWalletButton = document.getElementById('key-wallet-button');
const keyWalletModal = document.getElementById('key-wallet-modal');
const closeKeyWalletButton = document.getElementById('close-key-wallet');
const toast = document.getElementById('demo-toast');
const keyWalletPrivate = document.getElementById('key-wallet-private');
const keyWalletPublic = document.getElementById('key-wallet-public');
const keyWalletSecret = document.getElementById('key-wallet-secret');

const state = {
    activeUsers: [],
    localUsername: '',
    localKeyPair: null,
    localPublicJwk: null,
    peerSessions: new Map(),
    currentPeerId: null,
    currentPeerUsername: '',
    securityEnabled: true,
    hackerEnabled: false,
    lastExplanation: null
};

function showScreen(screenName) {
    const screens = {
        login: loginScreen,
        chat: chatScreen
    };

    Object.entries(screens).forEach(([name, screen]) => {
        screen.classList.toggle('active', name === screenName);
        screen.classList.toggle('hidden', name !== screenName);
    });
}

function sanitizeHistoryKey(peerName) {
    return String(peerName || 'peer').trim().replace(/[^a-zA-Z0-9_-]/g, '_');
}

function getHistoryStorageKey(peerName) {
    return `${STORAGE_KEYS.historyPrefix}${sanitizeHistoryKey(peerName)}`;
}

function renderLoginState() {
    const session = loadStoredUserSession();
    const hasSavedUser = Boolean(session);
    savedUserPanel.classList.toggle('hidden', !hasSavedUser);
    newUserForm.classList.toggle('hidden', hasSavedUser);

    if (hasSavedUser) {
        savedUsernameLabel.textContent = session.username;
    }
}

function loadStoredUserSession() {
    try {
        const raw = localStorage.getItem(STORAGE_KEYS.userSession);
        if (!raw) {
            return null;
        }

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
        console.error('Failed to load stored history:', error);
        return [];
    }
}

function appendMessageToHistory(peerName, message, direction) {
    if (!peerName) {
        return;
    }

    const history = loadStoredHistory(peerName);
    history.push({ message, direction });
    localStorage.setItem(getHistoryStorageKey(peerName), JSON.stringify(history));
}

function renderHistoryForPeer(peerName) {
    if (!peerName) {
        messageLog.innerHTML = '';
        return;
    }

    messageLog.innerHTML = '';
    const history = loadStoredHistory(peerName);
    history.forEach((entry) => {
        const className = entry.direction === 'sent' ? 'sent' : 'received';
        displayMessage(entry.message, className);
    });
}

function clearPeerHistory(peerName) {
    if (!peerName) {
        return;
    }

    localStorage.removeItem(getHistoryStorageKey(peerName));
    messageLog.innerHTML = '';
}

function showToast(message) {
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(showToast.timeoutId);
    showToast.timeoutId = window.setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function updateConnectionStatus(isConnected) {
    connectionStatus.classList.toggle('connected', isConnected);
    connectionStatus.classList.toggle('disconnected', !isConnected);
    connectionStatus.textContent = isConnected ? 'Online' : 'Offline';
}

function updateToggleButtons() {
    securityToggle.classList.toggle('active', state.securityEnabled);
    securityToggle.textContent = `🔒 Secure Chat (Encryption)${state.securityEnabled ? '' : ' • OFF'}`;

    hackerToggle.classList.toggle('active', state.hackerEnabled);
    hackerToggle.textContent = `👾 Simulate Hacker Attack${state.hackerEnabled ? '' : ' • OFF'}`;
}

function displayMessage(message, type) {
    const div = document.createElement('div');
    div.classList.add('message-item', type);
    div.textContent = message;
    messageLog.appendChild(div);
    messageLog.scrollTop = messageLog.scrollHeight;
}

function updateChatHeader() {
    if (state.currentPeerId) {
        chatPartner.textContent = state.currentPeerUsername;
    } else {
        chatPartner.textContent = 'Pick a person';
    }
}

function createExplanationCard(mode, detailText) {
    const card = document.getElementById('explanation-card');
    card.className = `explanation-card ${mode}`;
    card.innerHTML = detailText;
}

function updateExplanationCardForState() {
    if (!state.lastExplanation) {
        createExplanationCard('neutral', 'Choose a person to start a secure conversation.');
        return;
    }

    const { mode, detailText } = state.lastExplanation;
    createExplanationCard(mode, detailText);
}

function setExplanationForPlaintext(rawMessage) {
    const safeText = String(rawMessage || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    state.lastExplanation = {
        mode: 'danger',
        detailText: `
            <strong>Encryption is OFF.</strong> The message was sent as plain text.<br><br>
            <strong>What the Hacker sees:</strong> ${safeText}<br><br>
            <strong>Risk:</strong> Anyone observing the network can read the message instantly.
        `
    };
    updateExplanationCardForState();
}

function buildSecureTimeline(direction, ciphertext, plaintext, isTampered = false) {
    const safeCiphertext = String(ciphertext || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const safePlaintext = String(plaintext || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    if (direction === 'sent') {
        const hackerNote = isTampered
            ? '<div class="tamper-note">Hacker Mode: This message will be altered in transit.</div>'
            : '';

        return `
            <div class="timeline">
                <div class="timeline-step">
                    <span class="step-marker">1</span>
                    <div class="step-body">
                        <span class="step-tag">Step 1</span>
                        <p>The Secret Handshake: Your device and their device mathematically created a shared password without ever sending it over the internet.</p>
                    </div>
                </div>
                <div class="timeline-step">
                    <span class="step-marker">2</span>
                    <div class="step-body">
                        <span class="step-tag">Step 2</span>
                        <p>The Digital Lock: Your message was scrambled using that shared password.</p>
                    </div>
                </div>
                <div class="timeline-step">
                    <span class="step-marker">3</span>
                    <div class="step-body">
                        <span class="step-tag">Step 3</span>
                        <p>What the Internet Sees: <strong>${safeCiphertext}</strong>.</p>
                        ${hackerNote}
                    </div>
                </div>
            </div>
        `;
    }

    return `
        <div class="timeline">
            <div class="timeline-step">
                <span class="step-marker">1</span>
                <div class="step-body">
                    <span class="step-tag">Step 1</span>
                    <p>Received Scrambled Text: <strong>${safeCiphertext}</strong>.</p>
                </div>
            </div>
            <div class="timeline-step">
                <span class="step-marker">2</span>
                <div class="step-body">
                    <span class="step-tag">Step 2</span>
                    <p>The Secret Handshake: Your device used its own private key to recreate the exact same shared password.</p>
                </div>
            </div>
            <div class="timeline-step">
                <span class="step-marker">3</span>
                <div class="step-body">
                    <span class="step-tag">Step 3</span>
                    <p>The Unlock: The lock matched perfectly, proving nobody tampered with it, and the text was unscrambled.</p>
                    <span class="code-snippet">Plain text: ${safePlaintext}</span>
                </div>
            </div>
        </div>
    `;
}

function setExplanationForEncrypted(ciphertext, originalMessage, direction = 'sent', isTampered = false) {
    state.lastExplanation = {
        mode: 'safe',
        detailText: buildSecureTimeline(direction, ciphertext, originalMessage, isTampered)
    };

    updateExplanationCardForState();
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
        console.error('Failed to restore session keypair:', error);
        return null;
    }
}

async function continueSavedSession() {
    const userSession = loadStoredUserSession();
    if (!userSession) {
        return;
    }

    const restored = await restoreKeyPairFromStorage(userSession);
    if (!restored) {
        clearStoredUserSession();
        renderLoginState();
        return;
    }

    state.localUsername = userSession.username;
    state.localKeyPair = restored;
    state.localPublicJwk = userSession.publicKeyJwk;
    activeUserBadge.textContent = `You: ${userSession.username}`;
    showScreen('chat');
    displayMessage(`Welcome back, ${userSession.username}.`, 'system');
    updateConnectionStatus(socket.connected);
    renderActiveUsers();
}

async function registerUser(username) {
    if (!window.crypto || !window.crypto.subtle) {
        displayMessage('Your browser does not support Web Crypto.', 'system-error');
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

        state.localUsername = username.trim();
        state.localKeyPair = keyPair;
        state.localPublicJwk = publicKeyJwk;
        activeUserBadge.textContent = `You: ${state.localUsername}`;

        persistStoredUserSession(state.localUsername, publicKeyJwk, privateKeyJwk);
        renderLoginState();
        showScreen('chat');
        displayMessage(`Joined as ${state.localUsername}.`, 'system');
        updateChatHeader();
        renderActiveUsers();
        socket.emit('register-user', { username: state.localUsername, publicKey: publicKeyJwk });
    } catch (error) {
        console.error('Registration failed:', error);
        displayMessage('Unable to set up your secure identity.', 'system-error');
    }
}

function renderActiveUsers() {
    const peers = state.activeUsers.filter((user) => user.id !== socket.id);
    activeUsersList.innerHTML = '';

    if (peers.length === 0) {
        const emptyCard = document.createElement('div');
        emptyCard.className = 'person-card';
        emptyCard.innerHTML = '<div><h3>No one online</h3><span>Wait for another participant to join.</span></div>';
        activeUsersList.appendChild(emptyCard);
        return;
    }

    peers.forEach((user) => {
        const card = document.createElement('div');
        card.className = 'person-card';
        card.innerHTML = `
            <div>
                <h3>${user.username}</h3>
                <span>Ready to chat</span>
            </div>
            <button class="user-action-btn" data-peer-id="${user.id}" data-peer-name="${user.username}">Chat</button>
        `;
        activeUsersList.appendChild(card);
    });

    activeUsersList.querySelectorAll('.user-action-btn').forEach((button) => {
        button.addEventListener('click', () => {
            startSecureChat(button.dataset.peerId, button.dataset.peerName);
        });
    });
}

function setKeyWalletVisibility(isOpen) {
    keyWalletModal.classList.toggle('hidden', !isOpen);
    keyWalletModal.setAttribute('aria-hidden', String(!isOpen));
}

function truncateForDisplay(value, maxLength = 84) {
    if (!value) {
        return 'Not available yet.';
    }

    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
}

async function renderKeyWallet() {
    const fallbackSession = loadStoredUserSession();
    const privateKey = state.localKeyPair
        ? await crypto.subtle.exportKey('jwk', state.localKeyPair.privateKey)
        : fallbackSession?.privateKeyJwk || null;
    const publicKey = state.localKeyPair
        ? await crypto.subtle.exportKey('jwk', state.localKeyPair.publicKey)
        : fallbackSession?.publicKeyJwk || null;

    keyWalletPrivate.textContent = privateKey ? truncateForDisplay(JSON.stringify(privateKey, null, 2), 280) : 'Not available yet.';
    keyWalletPublic.textContent = publicKey ? JSON.stringify(publicKey, null, 2) : 'Not available yet.';

    const peerSession = state.currentPeerId ? state.peerSessions.get(state.currentPeerId) : null;
    if (peerSession && peerSession.sharedSecret) {
        try {
            const rawSecret = await crypto.subtle.exportKey('raw', peerSession.sharedSecret);
            const hex = Array.from(new Uint8Array(rawSecret))
                .map((byte) => byte.toString(16).padStart(2, '0'))
                .join('');
            keyWalletSecret.textContent = `${hex.slice(0, 96)}${hex.length > 96 ? '…' : ''}\n\nDerived from the ECDH shared secret and used as the AES-GCM key.`;
        } catch (error) {
            console.error('Failed to export shared secret:', error);
            keyWalletSecret.textContent = 'Shared secret is present in memory but could not be exported for display.';
        }
    } else {
        keyWalletSecret.textContent = 'No active shared secret yet. Start a secure chat to derive the AES-GCM key.';
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
            sharedSecret
        };

        state.peerSessions.set(peerId, session);
        state.currentPeerId = peerId;
        state.currentPeerUsername = peer.username;
        updateChatHeader();
        renderHistoryForPeer(peer.username);
        return session;
    } catch (error) {
        console.error('Failed to derive peer session:', error);
        return null;
    }
}

async function startSecureChat(peerId, peerName) {
    const peer = state.activeUsers.find((user) => user.id === peerId);
    if (!peer || !state.localKeyPair) {
        return;
    }

    state.currentPeerId = peerId;
    state.currentPeerUsername = peerName;
    updateChatHeader();

    const session = await deriveSessionWithPeer(peerId);
    if (!session) {
        displayMessage('Unable to start a secure session with this user.', 'system-error');
        return;
    }

    messageInput.focus();
    displayMessage(`Connected with ${peerName}.`, 'system');
}

function emitToggleState(toggle, enabled) {
    if (!state.currentPeerId) {
        return;
    }

    socket.emit('toggle-sync', {
        recipientId: state.currentPeerId,
        senderId: socket.id,
        toggle,
        enabled
    });
}

function applyRemoteToggle(toggle, enabled) {
    if (toggle === 'security') {
        state.securityEnabled = Boolean(enabled);
        if (!state.securityEnabled) {
            state.hackerEnabled = false;
        }
    }

    if (toggle === 'hacker') {
        if (!state.securityEnabled) {
            state.hackerEnabled = false;
        } else {
            state.hackerEnabled = Boolean(enabled);
        }
    }

    updateToggleButtons();
    showToast(`Peer updated ${toggle === 'security' ? 'Secure Chat' : 'Hacker Attack'} to ${state[toggle === 'security' ? 'securityEnabled' : 'hackerEnabled'] ? 'ON' : 'OFF'}.`);
    updateExplanationCardForState();
}

function handlePlaintextSend(message) {
    const payload = {
        senderId: socket.id,
        recipientId: state.currentPeerId,
        isPlaintext: true,
        message
    };

    socket.emit('private-message', payload);
    displayMessage(`You: ${message}`, 'sent-plaintext');
    appendMessageToHistory(state.currentPeerUsername, `You: ${message}`, 'sent');
    setExplanationForPlaintext(message);
    messageInput.value = '';
}

async function handleEncryptedSend(message) {
    const session = state.peerSessions.get(state.currentPeerId);
    if (!session) {
        displayMessage('Secure channel is not ready yet.', 'system-error');
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

        const originalCiphertextBase64 = bufferToBase64(ciphertextBuffer);
        const outgoingCiphertextBase64 = state.hackerEnabled
            ? tamperCiphertext(originalCiphertextBase64)
            : originalCiphertextBase64;

        socket.emit('private-message', {
            recipientId: state.currentPeerId,
            senderId: socket.id,
            iv: bufferToBase64(iv),
            ciphertext: outgoingCiphertextBase64
        });

        displayMessage(`You: ${message}`, 'sent');
        appendMessageToHistory(state.currentPeerUsername, `You: ${message}`, 'sent');
        setExplanationForEncrypted(originalCiphertextBase64, message, 'sent', state.hackerEnabled);
        messageInput.value = '';
    } catch (error) {
        console.error('Encryption failed:', error);
        displayMessage('Unable to encrypt this message.', 'system-error');
    }
}

async function handleIncomingMessage(data) {
    if (!data || !data.senderId) {
        return;
    }

    const incomingData = data;
    const senderUsername = state.activeUsers.find((user) => user.id === incomingData.senderId)?.username || 'Peer';

    if (incomingData.isPlaintext) {
        const renderedMessage = `${senderUsername}: ${incomingData.message || ''}`;
        displayMessage(renderedMessage, 'received-plaintext');
        appendMessageToHistory(state.currentPeerUsername || senderUsername, renderedMessage, 'received');
        setExplanationForPlaintext(incomingData.message);
        return;
    }

    let session = state.peerSessions.get(incomingData.senderId);
    if (!session) {
        session = await deriveSessionWithPeer(incomingData.senderId);
    }

    if (!session) {
        displayMessage('The incoming message could not be verified.', 'system-error');
        return;
    }

    try {
        const ivBuffer = base64ToBuffer(incomingData.iv);
        const ciphertextBuffer = base64ToBuffer(incomingData.ciphertext);
        const decryptedBytes = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            session.sharedSecret,
            ciphertextBuffer
        );

        const plaintext = new TextDecoder().decode(decryptedBytes);
        const renderedMessage = `${senderUsername}: ${plaintext}`;
        displayMessage(renderedMessage, 'received');
        appendMessageToHistory(state.currentPeerUsername || senderUsername, renderedMessage, 'received');
        setExplanationForEncrypted(incomingData.ciphertext, plaintext, 'received');
    } catch (error) {
        console.error('Decryption failed:', error);
        displayMessage('The encrypted message was rejected.', 'system-error');
        state.lastExplanation = {
            mode: 'warning',
            detailText: '<strong>Decryption Blocked!</strong> The message was altered by a hacker in transit. Your device detected that the mathematical lock was broken and rejected the message to keep you safe.'
        };
        updateExplanationCardForState();
    }
}

joinButton.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
        alert('Please enter a name first.');
        return;
    }

    await registerUser(username);
    usernameInput.value = '';
});

welcomeBackButton.addEventListener('click', async () => {
    await continueSavedSession();
});

differentUserButton.addEventListener('click', () => {
    clearStoredUserSession();
    renderLoginState();
    usernameInput.value = '';
    usernameInput.focus();
});

clearChatButton.addEventListener('click', () => {
    if (!state.currentPeerUsername) {
        showToast('Chat history cleared.');
        return;
    }

    clearPeerHistory(state.currentPeerUsername);
    showToast('Chat history cleared.');
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
    messageLog.innerHTML = '';
    state.lastExplanation = null;
    updateExplanationCardForState();
    window.location.reload();
});

keyWalletButton.addEventListener('click', async () => {
    await renderKeyWallet();
    setKeyWalletVisibility(true);
});

closeKeyWalletButton.addEventListener('click', () => setKeyWalletVisibility(false));
keyWalletModal.addEventListener('click', (event) => {
    if (event.target && event.target.dataset && event.target.dataset.closeWallet === 'true') {
        setKeyWalletVisibility(false);
    }
});

document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !keyWalletModal.classList.contains('hidden')) {
        setKeyWalletVisibility(false);
    }
});

securityToggle.addEventListener('click', () => {
    const nextSecurityState = !state.securityEnabled;
    state.securityEnabled = nextSecurityState;

    if (!state.securityEnabled) {
        state.hackerEnabled = false;
    }

    updateToggleButtons();
    emitToggleState('security', state.securityEnabled);
    if (!state.securityEnabled) {
        emitToggleState('hacker', false);
    }
    showToast(state.securityEnabled ? 'E2EE Enabled: AES-GCM authenticated encryption active.' : 'E2EE Disabled: Transmitting insecure plaintext over the network.');

    if (!state.currentPeerId) {
        state.lastExplanation = state.securityEnabled ? {
            mode: 'safe',
            detailText: '<strong>Encryption is ON.</strong> The message was locked before leaving the computer.'
        } : {
            mode: 'danger',
            detailText: '<strong>Encryption is OFF.</strong> The message was sent as plain text.'
        };
        updateExplanationCardForState();
    }
});

hackerToggle.addEventListener('click', () => {
    if (!state.securityEnabled) {
        state.hackerEnabled = false;
        updateToggleButtons();
        showToast('Turn on Secure Chat before simulating a hacker attack.');
        return;
    }

    state.hackerEnabled = !state.hackerEnabled;
    updateToggleButtons();
    emitToggleState('hacker', state.hackerEnabled);
    showToast(state.hackerEnabled ? 'MITM Simulation Active: Injecting bit-flip errors during transit.' : 'MITM Simulation Inactive: Transit integrity remains unmodified.');

    if (state.lastExplanation && state.lastExplanation.mode === 'safe') {
        setExplanationForEncrypted('ciphertext example', 'sample message');
    }
});

sendButton.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    if (!message) {
        return;
    }

    if (!state.currentPeerId) {
        displayMessage('Choose a person before sending a message.', 'system-error');
        return;
    }

    if (!state.securityEnabled) {
        handlePlaintextSend(message);
        return;
    }

    await handleEncryptedSend(message);
});

messageInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        sendButton.click();
    }
});

socket.on('connect', () => {
    updateConnectionStatus(true);
    if (state.localUsername && state.localKeyPair && state.localPublicJwk) {
        socket.emit('register-user', { username: state.localUsername, publicKey: state.localPublicJwk });
    }
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

socket.on('active-users', (users) => {
    state.activeUsers = users;
    renderActiveUsers();

    if (state.currentPeerId && !users.some((user) => user.id === state.currentPeerId)) {
        state.currentPeerId = null;
        state.currentPeerUsername = '';
        state.peerSessions.clear();
        updateChatHeader();
        state.lastExplanation = null;
        updateExplanationCardForState();
        displayMessage('That person left the chat. Pick someone else.', 'system');
    }
});

socket.on('toggle-sync', ({ senderId, toggle, enabled }) => {
    if (!senderId || senderId === socket.id) {
        return;
    }

    applyRemoteToggle(toggle, enabled);
    if (toggle === 'security' && state.currentPeerId === senderId) {
        showToast(`Your chat partner changed Secure Chat to ${enabled ? 'ON' : 'OFF'}.`);
    }
});

socket.on('private-message', async (data) => {
    await handleIncomingMessage(data);
});

showScreen('login');
updateConnectionStatus(false);
updateToggleButtons();
updateChatHeader();
updateExplanationCardForState();
renderLoginState();
setKeyWalletVisibility(false);

const session = loadStoredUserSession();
if (session) {
    savedUsernameLabel.textContent = session.username;
}

(async () => {
    const restored = loadStoredUserSession();
    if (restored) {
        const keyPair = await restoreKeyPairFromStorage(restored);
        if (keyPair) {
            state.localUsername = restored.username;
            state.localKeyPair = keyPair;
            state.localPublicJwk = restored.publicKeyJwk;
            activeUserBadge.textContent = `You: ${restored.username}`;
        }
    }
})();
