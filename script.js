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

// Event listeners for encrypt button
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const plaintext = document.getElementById('encryptInputText').value.trim();
    const password = document.getElementById('encryptPassword').value.trim();
    const method = document.getElementById('encryptMethodSelect').value;
    let ciphertext = '';

    if (!plaintext) {
        alert('Le texte à crypter ne peut pas être vide.');
        return;
    }

    if (method === 'aes-gcm' && !password) {
        alert('Le mot de passe est requis pour AES-GCM.');
        return;
    }

    try {
        switch (method) {
            case 'aes-gcm':
                ciphertext = await encryptAESGCM(password, plaintext);
                break;
            case 'base64':
                ciphertext = encodeBase64(plaintext);
                break;
            default:
                alert('Méthode de cryptage non supportée');
                return;
        }

        document.getElementById('encryptOutputText').value = ciphertext;
    } catch (error) {
        console.error('Erreur lors du cryptage:', error);
        alert('Une erreur est survenue lors du cryptage.');
    }
});

// Event listeners for decrypt button
document.getElementById('decryptBtn').addEventListener('click', async () => {
    const ciphertext = document.getElementById('decryptInputText').value.trim();
    const password = document.getElementById('decryptPassword').value.trim();
    const method = document.getElementById('decryptMethodSelect').value;
    let plaintext = '';

    if (!ciphertext) {
        alert('Le texte à décrypter ne peut pas être vide.');
        return;
    }

    if (method === 'aes-gcm' && !password) {
        alert('Le mot de passe est requis pour AES-GCM.');
        return;
    }

    try {
        switch (method) {
            case 'aes-gcm':
                plaintext = await decryptAESGCM(password, ciphertext);
                break;
            case 'base64':
                plaintext = decodeBase64(ciphertext);
                break;
            default:
                alert('Méthode de décryptage non supportée');
                return;
        }

        if (plaintext === null) {
            alert('Le décryptage a échoué.');
        } else {
            document.getElementById('decryptOutputText').value = plaintext;
        }
    } catch (error) {
        console.error('Erreur lors du décryptage:', error);
        alert('Une erreur est survenue lors du décryptage.');
    }
});