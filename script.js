// AES-GCM encryption and decryption
async function encryptAESGCM(password, plaintext) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        enc.encode(plaintext)
    );
    const ctArray = new Uint8Array(ciphertext);
    const ctStr = ctArray.reduce((data, byte) => data + String.fromCharCode(byte), '');
    const ivStr = Array.from(iv).map(b => String.fromCharCode(b)).join('');
    const saltStr = Array.from(salt).map(b => String.fromCharCode(b)).join('');
    return btoa(saltStr + ivStr + ctStr);
}

async function decryptAESGCM(password, ciphertext) {
    const enc = new TextEncoder();
    const data = atob(ciphertext);
    const salt = new Uint8Array(Array.from(data.slice(0, 16)).map(ch => ch.charCodeAt(0)));
    const iv = new Uint8Array(Array.from(data.slice(16, 28)).map(ch => ch.charCodeAt(0)));
    const ct = new Uint8Array(Array.from(data.slice(28)).map(ch => ch.charCodeAt(0)));
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    try {
        const plaintext = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            ct
        );
        const dec = new TextDecoder();
        return dec.decode(plaintext);
    } catch (e) {
        console.error('Decryption failed:', e);
        return null;
    }
}

// Base64 encoding and decoding
function encodeBase64(plaintext) {
    return btoa(plaintext);
}

function decodeBase64(ciphertext) {
    try {
        return atob(ciphertext);
    } catch (e) {
        console.error('Base64 decoding failed:', e);
        return null;
    }
}

// Function to toggle password visibility
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    if (field.type === "password") {
        field.type = "text";
    } else {
        field.type = "password";
    }
}

// Event listeners for encrypt button
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const plaintext = document.getElementById('encryptInputText').value;
    const password = document.getElementById('encryptPassword').value;
    const method = document.getElementById('encryptMethodSelect').value;
    let ciphertext = '';

    switch (method) {
        case 'aes-gcm':
            ciphertext = await encryptAESGCM(password, plaintext);
            break;
        case 'base64':
            ciphertext = encodeBase64(plaintext);
            break;
        // Add other methods here
        default:
            alert('Méthode de cryptage non supportée');
            return;
    }

    document.getElementById('encryptOutputText').value = ciphertext;
});

// Event listeners for decrypt button
document.getElementById('decryptBtn').addEventListener('click', async () => {
    const ciphertext = document.getElementById('decryptInputText').value;
    const password = document.getElementById('decryptPassword').value;
    const method = document.getElementById('decryptMethodSelect').value;
    let plaintext = '';

    switch (method) {
        case 'aes-gcm':
            plaintext = await decryptAESGCM(password, ciphertext);
            break;
        case 'base64':
            plaintext = decodeBase64(ciphertext);
            break;
        // Add other methods here
        default:
            alert('Méthode de cryptage non supportée ou non décryptable');
            return;
    }

    if (plaintext === null) {
        alert('Le décryptage a échoué');
    } else {
        document.getElementById('decryptOutputText').value = plaintext;
    }
});