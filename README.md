# Zero-Trust E2EE Chat Application

[![Live Demo](https://img.shields.io/badge/Live_Demo-Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://e2ee-crypto-chat.onrender.com)
[![GitHub Repo](https://img.shields.io/badge/Source_Code-GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Harsha4114N/e2ee-crypto-chat)

A decentralized, Zero-Trust chat application demonstrating client-side cryptographic engineering. It utilizes a blind Node.js/Socket.io relay backend that routes traffic without ever accessing plaintext. All cryptographic operations—key generation, shared secret derivation, and payload encryption—occur strictly client-side via the browser's native Web Crypto API.

---

## Live Demonstration

<!-- DRAG AND DROP YOUR VIDEO FILE (.MP4) ON THE EMPTY LINE BELOW -->


* **Live Deployment:** [https://e2ee-crypto-chat.onrender.com](https://e2ee-crypto-chat.onrender.com)
* **Architecture Walkthrough:** [Watch the demo video on LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:7506742088198430720/)

---

## Core Cryptographic Features

* **ECDH Key Exchange:** Utilizes the NIST P-256 elliptic curve for secure shared secret derivation without transmitting private keys.
* **AES-256-GCM Encryption:** Secures message confidentiality while providing a 128-bit authentication tag for data integrity.
* **Cryptographic Key Wallet:** Allows users to inspect raw JSON Web Keys (JWK) and hexadecimal secrets in real time.
* **MITM Interception Simulator:** Proves GCM integrity by actively flipping transit bits and triggering rejection protocols.
* **Client-Side Persistence:** Anchors cryptographic identities and chat histories securely in the browser's local storage.
* **Split-Screen Educational UI:** Dynamically translates complex mathematical pipelines into accessible English explanations.

---

## Step-by-Step Local Setup

To run this project on a local machine for testing or offline presentations:

1. Clone the repository:
   ```bash
   git clone [https://github.com/Harsha4114N/e2ee-crypto-chat.git](https://github.com/Harsha4114N/e2ee-crypto-chat.git)

Navigate into the project folder: cd e2ee-crypto-chat
Install dependencies: npm install
Start the server: node server.js
Open two separate web browser windows at http://localhost:3000 to test the connection.

##Demonstration Guide
When evaluating or presenting the application:

Unencrypted Baseline: Leave the security toggle OFF to show how standard networks expose plaintext on the wire.

E2EE Protocol Active: Toggle Security ON to demonstrate AES-256-GCM encryption and open the Key Wallet to inspect raw P-256 keys.

Integrity Enforcement: Enable the Hacker Simulator to inject bit errors in transit, demonstrating how Galois/Counter Mode mathematically detects tampered ciphertext and blocks decryption.



https://github.com/user-attachments/assets/de855e78-c3f1-45bc-b4a8-cf3a360c2583

