(() => {
  const ROOT_ID = 'phishguard-root';
  if (document.getElementById(ROOT_ID)) return;

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function setStatus(text, isError = false) {
    status.textContent = text || '';
    status.className = isError ? 'phg-error' : 'phg-ok';
  }

  async function uploadFile(file) {
    if (!file) return;
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!['eml', 'msg'].includes(ext)) {
      setStatus('Format non supporté. Choisis un fichier .eml ou .msg', true);
      return;
    }

    fileInfo.textContent = `Fichier sélectionné : ${file.name} (${Math.round(file.size / 1024)} Ko)`;
    result.innerHTML = '';
    setStatus('Envoi au backend et analyse en cours...');

    try {
      const buffer = await file.arrayBuffer();
      chrome.runtime.sendMessage(
        {
          type: 'PHISHGUARD_UPLOAD_FILE',
          filename: file.name,
          mimeType: file.type || (ext === 'msg' ? 'application/vnd.ms-outlook' : 'message/rfc822'),
          bytes: Array.from(new Uint8Array(buffer)),
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
          setStatus('Analyse terminée. Le fichier temporaire backend a été supprimé ; les pièces jointes ne sont sauvegardées que si le backend a été configuré pour cela.');
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
      <div class="phg-row"><strong>Sous-scores :</strong><br>
        Texte: ${escapeHtml(comp.text ?? 0)} |
        URL: ${escapeHtml(comp.url ?? 0)} |
        Headers: ${escapeHtml(comp.headers ?? 0)} |
        Domaine: ${escapeHtml(comp.domain ?? 0)} |
        Réputation: ${escapeHtml(comp.reputation ?? 0)} |
        Pièces jointes: ${escapeHtml(comp.attachments ?? 0)} |
        ML: ${escapeHtml(comp.ml ?? 0)} |
        Bénin: ${escapeHtml(comp.benign ?? 0)}
      </div>
      <div class="phg-row"><strong>Raisons principales :</strong>
        <ul>${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
      </div>
    `;
  }

  const root = document.createElement('div');
  root.id = ROOT_ID;
  root.innerHTML = `
    <button id="phishguard-launcher" type="button">Analyser un email</button>
    <div id="phishguard-panel" aria-live="polite">
      <h2>PhishGuard</h2>
      <div class="phg-row phg-help">
        1. Télécharge le mail depuis ton webmail au format <strong>.eml</strong> ou <strong>.msg</strong>.<br>
        2. Dépose-le ici ou clique pour le sélectionner.<br>
        3. L’extension l’envoie au backend Python local pour analyse.
      </div>
      <div class="phg-row" id="phishguard-dropzone">Déposer un fichier .eml / .msg ici ou cliquer pour sélectionner</div>
      <input id="phishguard-input" type="file" accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook" style="display:none">
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
