const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // When a user joins a room (for simplicity, we'll use a fixed room for now)
    socket.on('join-room', (roomId) => {
        socket.join(roomId);
        console.log(`User ${socket.id} joined room ${roomId}`);
        // Broadcast to all other users in the room that a new user has joined
        socket.to(roomId).emit('user-joined', socket.id);
    });

    // Blind relay for public-key-exchange: forwards public key to other peers in the room
    socket.on('public-key-exchange', (data) => {
        console.log(`Relaying public-key-exchange from ${socket.id} to room ${data.roomId}`);
        socket.to(data.roomId).emit('public-key-exchange', { senderId: socket.id, publicKey: data.publicKey });
    });

    // Blind relay for chat-message: forwards ciphertext and IV to other peers in the room
    socket.on('chat-message', (data) => {
        console.log(`Relaying chat-message from ${socket.id} to room ${data.roomId}`);
        socket.to(data.roomId).emit('chat-message', { senderId: socket.id, ciphertext: data.ciphertext, iv: data.iv });
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        // In a real application, you might want to broadcast a 'user-left' event
    });
});

server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
