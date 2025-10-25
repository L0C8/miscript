class AESCipher {
    static async generateKey() {
        return await crypto.subtle.generateKey(
            {
                name: 'AES-CBC',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    static async encrypt(plaintext, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(16));
        
        // Add PKCS7 padding
        const blockSize = 16;
        const padLen = blockSize - (data.length % blockSize) || blockSize;
        const pad = new Uint8Array(padLen).fill(padLen);
        const paddedData = new Uint8Array([...data, ...pad]);

        // Encrypt
        const encryptedBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-CBC',
                iv: iv
            },
            key,
            paddedData
        );

        // Combine IV and ciphertext
        const result = new Uint8Array(iv.length + encryptedBuffer.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encryptedBuffer), iv.length);

        // Base64 encode
        return btoa(String.fromCharCode(...result));
    }

    static async decrypt(encryptedText, key) {
        try {
            // Base64 decode
            const encryptedArray = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
            
            // Extract IV and ciphertext
            const iv = encryptedArray.slice(0, 16);
            const ciphertext = encryptedArray.slice(16);

            // Decrypt
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                ciphertext
            );

            // Remove PKCS7 padding
            const decryptedArray = new Uint8Array(decryptedBuffer);
            const padLen = decryptedArray[decryptedArray.length - 1];
            const unpadded = decryptedArray.slice(0, -padLen);

            // Convert to string
            return new TextDecoder().decode(unpadded);
        } catch (e) {
            return `Error decrypting: ${e.message}`;
        }
    }
}

class AESCipherPass {
    static async setKey(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const keyBytes = new Uint8Array(hashArray.slice(0, 16));
        
        return await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-CBC', length: 128 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    static async encrypt(plaintext, password) {
        const key = await this.setKey(password);
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(16));
        
        // Add PKCS7 padding
        const blockSize = 16;
        const padLen = blockSize - (data.length % blockSize) || blockSize;
        const pad = new Uint8Array(padLen).fill(padLen);
        const paddedData = new Uint8Array([...data, ...pad]);

        // Encrypt
        const encryptedBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-CBC',
                iv: iv
            },
            key,
            paddedData
        );

        // Combine IV and ciphertext
        const result = new Uint8Array(iv.length + encryptedBuffer.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encryptedBuffer), iv.length);

        // Base64 encode
        return btoa(String.fromCharCode(...result));
    }

    static async decrypt(ciphertext, password) {
        try {
            const key = await this.setKey(password);
            
            // Base64 decode
            const encryptedArray = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
            
            // Extract IV and ciphertext
            const iv = encryptedArray.slice(0, 16);
            const encryptedContent = encryptedArray.slice(16);

            // Decrypt
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                encryptedContent
            );

            // Remove PKCS7 padding
            const decryptedArray = new Uint8Array(decryptedBuffer);
            const padLen = decryptedArray[decryptedArray.length - 1];
            const unpadded = decryptedArray.slice(0, -padLen);

            // Convert to string
            return new TextDecoder().decode(unpadded);
        } catch (e) {
            return `Error decrypting: ${e.message}`;
        }
    }
}

// UI State and Elements
let currentKey = null;
let uiElements = null;

// UI Helper Functions
function initializeUIElements() {
    return {
        inputText: document.getElementById('input'),
        passwordInput: document.getElementById('password'),
        encryptBtn: document.getElementById('encryptBtn'),
        decryptBtn: document.getElementById('decryptBtn'),
        outputText: document.getElementById('output'),
        statusDiv: document.getElementById('status'),
        useKeyBtn: document.getElementById('useKeyBtn'),
        generateKeyBtn: document.getElementById('generateKeyBtn')
    };
}

function showStatus(message, isError = false) {
    uiElements.statusDiv.textContent = message;
    uiElements.statusDiv.className = isError ? 'status-error' : 'status-success';
}

function updateButtons() {
    const hasText = uiElements.inputText.value.trim();
    const hasPass = uiElements.passwordInput.value.trim();
    const hasKey = currentKey !== null;
    
    // Password-based encryption buttons
    uiElements.encryptBtn.disabled = !hasText || !hasPass;
    uiElements.decryptBtn.disabled = !hasText || !hasPass;
    
    // Key-based encryption buttons
    uiElements.useKeyBtn.disabled = !hasText || !hasKey;
}

// Core Functionality
async function generateNewKey() {
    try {
        currentKey = await AESCipher.generateKey();
        showStatus('New encryption key generated successfully!');
        updateButtons();
        uiElements.outputText.value = 'A new encryption key has been generated and is ready to use.';
    } catch (error) {
        showStatus(`Error generating key: ${error.message}`, true);
        uiElements.outputText.value = '';
    }
}

async function encryptWithKey() {
    try {
        const text = uiElements.inputText.value.trim();
        if (!text) {
            showStatus('Please enter text to encrypt', true);
            return;
        }
        if (!currentKey) {
            showStatus('Please generate a key first', true);
            return;
        }

        const encrypted = await AESCipher.encrypt(text, currentKey);
        uiElements.outputText.value = encrypted;
        showStatus('Encryption with key successful!');
    } catch (error) {
        showStatus(`Encryption error: ${error.message}`, true);
        uiElements.outputText.value = '';
    }
}

async function encryptWithPassword() {
    try {
        const text = uiElements.inputText.value.trim();
        const password = uiElements.passwordInput.value.trim();
        
        if (!text) {
            showStatus('Please enter text to encrypt', true);
            return;
        }
        if (!password) {
            showStatus('Please enter a password', true);
            return;
        }

        const encrypted = await AESCipherPass.encrypt(text, password);
        uiElements.outputText.value = encrypted;
        showStatus('Password-based encryption successful!');
    } catch (error) {
        showStatus(`Encryption error: ${error.message}`, true);
        uiElements.outputText.value = '';
    }
}

async function decryptWithPassword() {
    try {
        const ciphertext = uiElements.inputText.value.trim();
        const password = uiElements.passwordInput.value.trim();
        
        if (!ciphertext) {
            showStatus('Please enter text to decrypt', true);
            return;
        }
        if (!password) {
            showStatus('Please enter a password', true);
            return;
        }

        const decrypted = await AESCipherPass.decrypt(ciphertext, password);
        uiElements.outputText.value = decrypted;
        showStatus('Password-based decryption successful!');
    } catch (error) {
        showStatus(`Decryption error: ${error.message}`, true);
        uiElements.outputText.value = '';
    }
}

// Event Binding
function bindEventListeners() {
    uiElements.inputText.addEventListener('input', updateButtons);
    uiElements.passwordInput.addEventListener('input', updateButtons);
    uiElements.generateKeyBtn.addEventListener('click', generateNewKey);
    uiElements.useKeyBtn.addEventListener('click', encryptWithKey);
    uiElements.encryptBtn.addEventListener('click', encryptWithPassword);
    uiElements.decryptBtn.addEventListener('click', decryptWithPassword);
}

// Initialize UI
document.addEventListener('DOMContentLoaded', () => {
    uiElements = initializeUIElements();
    bindEventListeners();
    updateButtons();
});