# 🔐 End-to-End Encrypted Chat App

A secure, real-time chat application built with Node.js, Socket.io, and the Web Crypto API.

## 🚀 Features
- **Zero-Knowledge Architecture:** Private keys are encrypted on the client-side. The server never sees your real key.
- **End-to-End Encryption:** Messages, Images, and Videos are encrypted before leaving the browser.
- **Real-Time:** Instant messaging using WebSockets (Socket.io).
- **Secure File Sharing:** Encrypted file uploads (Images, Video, PDF).
- **Friend System:** Add/Remove friends with real-time request notifications.

## 🛠️ Tech Stack
- **Frontend:** HTML5, CSS3 (Glassmorphism UI), Vanilla JS, Web Crypto API
- **Backend:** Node.js, Express, Socket.io
- **Database:** Redis
- **Security:** ECDH Key Exchange, AES-GCM Encryption, Bcrypt

## 📦 How to Run
1. Clone the repo:
   ```bash
   git clone <https://github.com/albart-maker/Encryption-chat.git)>
2.Install dependencies:

Bash

npm install

3.Start Redis Server (Ensure Redis is installed):

Bash

redis-server

4.Start the App:

Bash

node server.js

5.Open http://localhost:3000 in your browser.


---

### **Step 3: Initialize Git (In your Terminal)**

Open your terminal inside your project folder and run these commands one by one:

1.  **Initialize Git:**
    ```bash
    git init
    ```

2.  **Add your files:**
    ```bash
    git add .
    ```
    *(If you did Step 1 correctly, this will NOT add node_modules).*

3.  **Commit your code:**
    ```bash
    git commit -m "Initial commit: Completed E2EE Chat Application"
    ```

---

### **Step 4: Create Repo on GitHub**

1.  Go to [GitHub.com](https://github.com) and log in.
2.  Click the **+** icon (top right) -> **New repository**.
3.  **Repository name:** `secure-chat-app` (or whatever you like).
4.  **Public/Private:** Choose Public.
5.  **Do NOT** check "Add a README" (we already made one).
6.  Click **Create repository**.

---

### **Step 5: Connect and Push**

GitHub will show you a page with commands. Look for the section **"…or push an existing repository from the command line"**.

Copy and run those commands. They will look like this (replace `YOUR_NAME` with your actual GitHub username):

```bash
git branch -M main
git remote add origin https://github.com/YOUR_NAME/secure-chat-app.git
git push -u origin main
