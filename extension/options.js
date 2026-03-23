const STORAGE_KEY = 'phishguard_backend_url';
const DEFAULT_BACKEND = 'http://127.0.0.1:8000';

const input = document.getElementById('backendUrl');
const saveBtn = document.getElementById('saveBtn');
const statusEl = document.getElementById('status');

chrome.storage.sync.get([STORAGE_KEY], (data) => {
  input.value = (data && data[STORAGE_KEY]) || DEFAULT_BACKEND;
});

saveBtn.addEventListener('click', () => {
  const value = String(input.value || '').trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(value)) {
    statusEl.textContent = "L'URL doit commencer par http:// ou https://";
    statusEl.style.color = 'darkred';
    return;
  }

  chrome.storage.sync.set({ [STORAGE_KEY]: value }, () => {
    statusEl.textContent = 'Configuration enregistrée.';
    statusEl.style.color = 'darkgreen';
  });
});
