const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;
const users = new Map();

app.use(express.static(path.join(__dirname, 'public')));

function getActiveUsers() {
    return Array.from(users.entries()).map(([socketId, user]) => ({
        id: socketId,
        username: user.username,
        publicKey: user.publicKey
    }));
}

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('register-user', ({ username, publicKey }) => {
        if (!username || typeof username !== 'string') {
            return;
        }

        users.set(socket.id, {
            username: username.trim(),
            publicKey
        });

        const activeUsers = getActiveUsers();
        io.emit('active-users', activeUsers);
        console.log(`Registered user ${username} (${socket.id}) with ${activeUsers.length} active users`);
    });

    socket.on('private-message', ({ recipientId, senderId, ciphertext, iv, isPlaintext, message }) => {
        if (!recipientId) {
            return;
        }

        const recipientSocket = io.sockets.sockets.get(recipientId);
        if (!recipientSocket) {
            return;
        }

        recipientSocket.emit('private-message', {
            senderId: senderId || socket.id,
            ciphertext,
            iv,
            isPlaintext: Boolean(isPlaintext),
            message
        });
    });

    socket.on('toggle-sync', ({ recipientId, senderId, toggle, enabled }) => {
        if (!recipientId || !toggle) {
            return;
        }

        const recipientSocket = io.sockets.sockets.get(recipientId);
        if (!recipientSocket) {
            return;
        }

        recipientSocket.emit('toggle-sync', {
            senderId: senderId || socket.id,
            toggle,
            enabled: Boolean(enabled)
        });
    });

    socket.on('disconnect', () => {
        if (users.has(socket.id)) {
            users.delete(socket.id);
            io.emit('active-users', getActiveUsers());
            console.log('User disconnected:', socket.id);
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
