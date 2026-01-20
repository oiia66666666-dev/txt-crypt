// 輔助函數
const base64ToArrayBuffer = base64 => {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
};

const arrayBufferToBase64 = buffer => {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary);
};

const textToArrayBuffer = text => {
    return new TextEncoder().encode(text);
};

const arrayBufferToText = buffer => {
    return new TextDecoder().decode(buffer);
};

// 加密相關的 Alpine.js 組件
window.encryptor = {
    text: '',
    password: '',
    iterations: 100000,
    encryptedUrl: '',
    isLoading: false,
    copyStatus: 'Copy URL',

    async encrypt() {
        try {
            this.isLoading = true;
            this.copyStatus = 'Copy URL';
            
            // 生成隨機 salt 和 iv
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // 從密碼生成金鑰
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                textToArrayBuffer(this.password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: parseInt(this.iterations),
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );
            
            // 加密
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                textToArrayBuffer(this.text)
            );
            
            // 組合 salt + iv + 密文
            const combined = new Uint8Array([
                ...salt,
                ...iv,
                ...new Uint8Array(encrypted)
            ]);
            
            // 轉成 base64 並產生 URL
            const base64 = arrayBufferToBase64(combined);
            const url = new URL(window.location.href);
            url.pathname = window.location.pathname + 'decrypt-simple.html';
            url.hash = base64;
            
            this.encryptedUrl = url.toString();
        } catch (error) {
            alert('Encryption failed: ' + error.message);
        } finally {
            this.isLoading = false;
        }
    },

    async copyUrl() {
        try {
            await navigator.clipboard.writeText(this.encryptedUrl);
            this.copyStatus = 'Copied!';
            setTimeout(() => {
                this.copyStatus = 'Copy URL';
            }, 2000);
        } catch (error) {
            console.error(error);
            alert('Copy failed: ' + error.message);
            this.copyStatus = 'Copy failed';
        }
    }
};

window.decryptor = {
    password: '',
    iterations: 100000,
    decryptedText: '',
    isLoading: false,
    error: '',
    copyStatus: '複製文字',

    async decrypt() {
        try {
            this.isLoading = true;
            this.error = '';
            
            // 從 URL 取得加密資料
            const base64 = window.location.hash.slice(1);
            if (!base64) {
                this.error = 'No encrypted data found';
                return;
            }
            
            // 解析出 salt、iv 和密文
            const combined = base64ToArrayBuffer(base64);
            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const encrypted = combined.slice(28);
            
            // 從密碼生成金鑰
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                textToArrayBuffer(this.password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: parseInt(this.iterations),
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            
            // 解密
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encrypted
            );
            
            this.decryptedText = arrayBufferToText(decrypted);
        } catch (error) {
            console.error(error);
            this.error = 'Decryption failed: ' + error.message;
        } finally {
            this.isLoading = false;
        }
    },

    reset() {
        this.decryptedText = '';
        this.error = '';
        this.copyStatus = '複製文字';
    },

    async copyText() {
        try {
            await navigator.clipboard.writeText(this.decryptedText);
            this.copyStatus = '已複製!';
            setTimeout(() => {
                this.copyStatus = '複製文字';
            }, 2000);
        } catch (error) {
            console.error(error);
            this.error = 'Copy failed: ' + error.message;
            this.copyStatus = '複製失敗';
        }
    }
}; 