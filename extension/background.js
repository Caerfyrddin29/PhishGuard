const STORAGE_KEY = 'phishguard_backend_url';
const DEFAULT_BACKEND = 'http://127.0.0.1:8000';

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get([STORAGE_KEY], (data) => {
    if (!data || !data[STORAGE_KEY]) {
      chrome.storage.sync.set({ [STORAGE_KEY]: DEFAULT_BACKEND });
    }
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'PHISHGUARD_UPLOAD_FILE') {
    handleFileUpload(message)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: normalizeError(error) }));
    return true;
  }

  if (message?.type === 'PHISHGUARD_GET_SETTINGS') {
    getBackendUrl()
      .then((url) => sendResponse({ ok: true, backendUrl: url }))
      .catch((error) => sendResponse({ ok: false, error: normalizeError(error) }));
    return true;
  }

  return false;
});

async function handleFileUpload(message) {
  const backend = await getBackendUrl();

  if (!message.filename || !message.base64) {
    throw new Error('Fichier incomplet ou invalide.');
  }

  const binary = atob(message.base64);
  const uint8 = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    uint8[i] = binary.charCodeAt(i);
  }
  const blob = new Blob([uint8], { type: message.mimeType || 'application/octet-stream' });
  const form = new FormData();
  form.append('file', blob, message.filename);

  const response = await fetch(`${backend}/analyze/file`, {
    method: 'POST',
    body: form
  });

  let data = {};
  try {
    data = await response.json();
  } catch (_) {}

  if (!response.ok) {
    throw new Error(data?.detail || `HTTP ${response.status}`);
  }
  return data;
}

function getBackendUrl() {
  return new Promise((resolve, reject) => {
    chrome.storage.sync.get([STORAGE_KEY], (data) => {
      try {
        resolve(sanitizeApiBaseUrl((data && data[STORAGE_KEY]) || DEFAULT_BACKEND));
      } catch (e) {
        reject(e);
      }
    });
  });
}

function sanitizeApiBaseUrl(url) {
  const clean = String(url || '').trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(clean)) {
    throw new Error("L'URL de l'API doit commencer par http:// ou https://");
  }
  return clean;
}

function normalizeError(error) {
  if (!error) return 'Erreur inconnue';
  if (typeof error === 'string') return error;
  return error.message || JSON.stringify(error);
}
