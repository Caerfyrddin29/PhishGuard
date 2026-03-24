(() => {
  const ROOT_ID = 'phishguard-root';
  const MAIL_HOST_PATTERNS = [
    /mail\.google\.com$/i,
    /outlook\.office\.com$/i,
    /outlook\.live\.com$/i,
    /mail\.yahoo\.com$/i,
    /proton\.me$/i,
    /mail\.proton\.me$/i,
    /mail\.protonmail\.com$/i,
    /roundcube/i,
    /webmail/i
  ];

  function shouldInject() {
    const host = location.hostname || '';
    const url = location.href || '';
    const title = document.title || '';
    if (MAIL_HOST_PATTERNS.some((rx) => rx.test(host))) return true;
    return /mail|inbox|gmail|outlook|webmail/i.test(host + ' ' + url + ' ' + title);
  }

  if (!shouldInject()) return;
  if (document.getElementById(ROOT_ID)) return;

  function setStatus(text, isError = false) {
    status.textContent = text || '';
    status.className = isError ? 'phg-error' : 'phg-ok';
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  async function uploadFile(file) {
    if (!file) return;

    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!['eml'].includes(ext)) {
      setStatus('Format non supporté. Choisis un fichier .eml', true);
      return;
    }

    fileInfo.textContent = `Fichier sélectionné : ${file.name} (${Math.round(file.size / 1024)} Ko)`;
    result.innerHTML = '';
    setStatus('Envoi au backend et analyse en cours...');

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);
      chrome.runtime.sendMessage(
        {
          type: 'PHISHGUARD_UPLOAD_FILE',
          filename: file.name,
          mimeType: file.type || 'message/rfc822',
          base64
        },
        (response) => {
          if (chrome.runtime.lastError) {
            setStatus(`Erreur extension : ${chrome.runtime.lastError.message}`, true);
            return;
          }
          if (!response || !response.ok) {
            setStatus(`Erreur : ${response?.error || 'Réponse invalide du background'}`, true);
            return;
          }
          renderResult(response.result);
          setStatus('Analyse terminée. Le backend a supprimé le fichier temporaire.');
        }
      );
    } catch (error) {
      setStatus(`Erreur : ${error.message}`, true);
    }
  }

  function renderResult(payload) {
    const analysis = payload?.analysis_result || {};
    const extracted = payload?.extracted_email || {};
    const reasons = Array.isArray(analysis.reasons) ? analysis.reasons.slice(0, 12) : [];
    const comp = analysis.sub_scores || {};
    const verdict = analysis.analysis_status === 'inconclusive'
      ? 'Analyse inconclusive'
      : analysis.verdict === 'phishing'
        ? 'Suspect (phishing)'
        : analysis.verdict === 'suspicious'
          ? 'Suspect'
          : 'Plutôt légitime';

    result.innerHTML = `
      <h3>Résultat</h3>
      <div class="phg-row">
        <span class="phg-badge">Verdict : ${escapeHtml(verdict)}</span>
        <span class="phg-badge">Score : ${escapeHtml(analysis.score ?? 'N/A')}/100</span>
        <span class="phg-badge">Confiance : ${escapeHtml(analysis.confidence ?? payload.extraction_confidence ?? 'N/A')}</span>
      </div>
      <div class="phg-row"><strong>Sujet :</strong> ${escapeHtml(extracted.subject || '(aucun)')}</div>
      <div class="phg-row"><strong>Expéditeur :</strong> ${escapeHtml(extracted.sender || '(inconnu)')}</div>
      <div class="phg-row"><strong>Type :</strong> ${escapeHtml(extracted.file_type || 'N/A')}</div>
      <div class="phg-row"><strong>Statut d'analyse :</strong> ${escapeHtml(analysis.analysis_status || payload.analysis_status || 'N/A')}</div>
      <div class="phg-row"><strong>Sous-scores :</strong><br>
        Texte: ${escapeHtml(comp.text ?? 0)} |
        URL: ${escapeHtml(comp.url ?? 0)} |
        Headers: ${escapeHtml(comp.headers ?? 0)} |
        Domaine: ${escapeHtml(comp.domain ?? 0)} |
        Réputation: ${escapeHtml(comp.reputation ?? 0)} |
        Pièces jointes: ${escapeHtml(comp.attachments ?? 0)} |
        ML: ${escapeHtml(comp.ml ?? 0)}
      </div>
      <div class="phg-row"><strong>Raisons principales :</strong>
        <ul>${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
      </div>
    `;
  }

  const root = document.createElement('div');
  root.id = ROOT_ID;
  root.innerHTML = `
    <button id="phishguard-launcher" type="button">Analyser un .eml</button>
    <div id="phishguard-panel" aria-live="polite">
      <h2>PhishGuard</h2>
      <div class="phg-row phg-help">
        1. Télécharge le mail depuis ton webmail au format <strong>.eml</strong>.<br>
        2. Dépose-le ici ou clique pour le sélectionner.<br>
        3. L’extension l’envoie au backend Python, qui l’analyse et supprime le fichier temporaire.
      </div>
      <div class="phg-row" id="phishguard-dropzone">Déposer un fichier .eml ici ou cliquer pour sélectionner</div>
      <input id="phishguard-input" type="file" accept=".eml,message/rfc822" style="display:none">
      <div class="phg-row" id="phishguard-fileinfo"></div>
      <div class="phg-row" id="phishguard-status"></div>
      <div class="phg-buttons phg-row">
        <button id="phishguard-open-options" type="button">Configurer l’API</button>
        <button id="phishguard-close" type="button">Fermer</button>
      </div>
      <div id="phishguard-result"></div>
    </div>
  `;
  document.documentElement.appendChild(root);

  const launcher = root.querySelector('#phishguard-launcher');
  const panel = root.querySelector('#phishguard-panel');
  const input = root.querySelector('#phishguard-input');
  const dropzone = root.querySelector('#phishguard-dropzone');
  const fileInfo = root.querySelector('#phishguard-fileinfo');
  const status = root.querySelector('#phishguard-status');
  const result = root.querySelector('#phishguard-result');
  const closeBtn = root.querySelector('#phishguard-close');
  const optionsBtn = root.querySelector('#phishguard-open-options');

  launcher.addEventListener('click', () => {
    panel.style.display = panel.style.display === 'block' ? 'none' : 'block';
  });
  closeBtn.addEventListener('click', () => { panel.style.display = 'none'; });
  optionsBtn.addEventListener('click', () => { if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage(); });
  dropzone.addEventListener('click', () => input.click());
  input.addEventListener('change', () => uploadFile(input.files?.[0]));

  ['dragenter', 'dragover'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.add('phg-dragover');
    });
  });
  ['dragleave', 'drop'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.remove('phg-dragover');
    });
  });
  dropzone.addEventListener('drop', (e) => uploadFile(e.dataTransfer?.files?.[0]));
})();
