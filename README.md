# Zero-Trust E2EE Chat Application

## Overview & Architecture
This project is a decentralized, Zero-Trust chat application designed to demonstrate real-world cryptographic principles. It utilizes a blind Node.js and Socket.io backend that routes traffic without ever accessing plaintext. All cryptographic operations—including key generation, derivation, and encryption—occur strictly client-side using the browser's native Web Crypto API.

## Core Cryptographic Features
*   **ECDH Key Exchange:** Utilizes the NIST P-256 elliptic curve for secure shared secret derivation without transmitting private keys.
*   **AES-256-GCM Encryption:** Secures message confidentiality while providing a 128-bit authentication tag for data integrity.
*   **Cryptographic Key Wallet:** Allows users to inspect raw JSON Web Keys (JWK) and hexadecimal secrets in real-time.
*   **MITM Interception Simulator:** Proves GCM integrity by actively flipping transit bits and triggering rejection protocols.
*   **Client-Side Persistence:** Anchors cryptographic identities and chat histories securely in the browser's local storage.
*   **Split-Screen Educational UI:** Dynamically translates complex mathematical pipelines into accessible English explanations.

## Step-by-Step Local Setup
To run this project on a local machine for testing or offline presentations, follow these exact steps:
1. Open your terminal and clone the repository using `git clone https://github.com/Harsha4114N/e2ee-crypto-chat.git`.
2. Navigate into the project folder by running `cd e2ee-crypto-chat`.
3. Install the required backend dependencies by executing `npm install`.
4. Start the local server by typing `node server.js`.
5. Open two separate web browser windows and navigate to `http://localhost:3000` to test the connection.

## Live Demonstration Guide
When presenting to evaluators, control the narrative using the built-in UI toggles. First, leave the security toggle **OFF** to show how standard networks expose plaintext on the wire. Next, toggle **Security ON** to demonstrate AES encryption and open the Key Wallet to prove the underlying math. Finally, enable the **Hacker Simulator** to show how Galois/Counter Mode mathematically detects and blocks tampered ciphertext.
