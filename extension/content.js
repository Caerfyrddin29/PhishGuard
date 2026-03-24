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
    const score = Number.isFinite(analysis.score) ? analysis.score : 'N/A';
    const confidence = analysis.confidence ?? payload.extraction_confidence ?? 'N/A';
    const verdictKey = analysis.verdict || 'legit';
    const verdict = analysis.analysis_status === 'inconclusive'
      ? 'Analyse inconclusive'
      : verdictKey === 'phishing'
        ? 'Phishing détecté'
        : verdictKey === 'suspicious'
          ? 'Message suspect'
          : 'Plutôt légitime';
    const badgeClass = verdictKey === 'phishing' ? 'phg-badge-danger' : verdictKey === 'suspicious' ? 'phg-badge-warn' : 'phg-badge-ok';

    result.innerHTML = `
      <h3>Résultat de l’analyse</h3>
      <div class="phg-badge-row">
        <span class="phg-badge ${badgeClass}">Verdict : ${escapeHtml(verdict)}</span>
        <span class="phg-badge">Score : ${escapeHtml(score)}/100</span>
        <span class="phg-badge">Confiance : ${escapeHtml(confidence)}</span>
      </div>

      <div class="phg-grid phg-row">
        <div class="phg-stat">
          <div class="phg-stat-label">Verdict</div>
          <div class="phg-stat-value">${escapeHtml(verdict)}</div>
        </div>
        <div class="phg-stat">
          <div class="phg-stat-label">Score global</div>
          <div class="phg-stat-value">${escapeHtml(score)}/100</div>
        </div>
      </div>

      <div class="phg-card phg-row">
        <h4>Résumé du message</h4>
        <div class="phg-meta-grid">
          <div class="phg-meta-item"><strong>Sujet</strong><span>${escapeHtml(extracted.subject || '(aucun)')}</span></div>
          <div class="phg-meta-item"><strong>Expéditeur</strong><span>${escapeHtml(extracted.sender || '(inconnu)')}</span></div>
          <div class="phg-meta-item"><strong>Type de fichier</strong><span>${escapeHtml(extracted.file_type || 'N/A')}</span></div>
        </div>
      </div>

      <div class="phg-card phg-row">
        <h4>Sous-scores</h4>
        <div class="phg-score-list">
          ${[
            ['Texte', comp.text ?? 0],
            ['Headers', comp.headers ?? 0],
            ['URLs', comp.url ?? 0],
            ['Domaine', comp.domain ?? 0],
            ['Réputation', comp.reputation ?? 0],
            ['Pièces jointes', comp.attachments ?? 0],
            ['ML', comp.ml ?? 0],
            ['Bénin', comp.benign ?? 0],
          ].map(([label, value]) => `<div class="phg-score-item"><span class="phg-score-label">${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}
        </div>
      </div>

      <div class="phg-card phg-row">
        <h4>Raisons principales</h4>
        ${reasons.length ? `<ul>${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>` : '<div class="phg-empty">Aucune raison détaillée n’a été renvoyée par le backend.</div>'}
      </div>
    `;
  }

  const root = document.createElement('div');
  root.id = ROOT_ID;
  root.innerHTML = `
    <button id="phishguard-launcher" type="button" aria-expanded="false">Analyser un email</button>
    <div id="phishguard-panel" aria-live="polite">
      <div class="phg-panel-header">
        <div>
          <h2>PhishGuard</h2>
          <div class="phg-panel-subtitle">Analyse locale de fichiers email <strong>.eml</strong> et <strong>.msg</strong></div>
        </div>
        <div class="phg-badge">Extension</div>
      </div>
      <div class="phg-card phg-row phg-help">
        1. Télécharge le mail depuis ton webmail.
        <br>2. Dépose le fichier ci-dessous ou clique pour le sélectionner.
        <br>3. L’extension l’envoie au backend Python local et affiche le verdict avec les raisons principales.
      </div>
      <div class="phg-row" id="phishguard-dropzone"><span class="phg-dropzone-title">Déposer un fichier .eml / .msg</span><span class="phg-dropzone-subtitle">Cliquer pour sélectionner ou glisser-déposer depuis ton explorateur</span></div>
      <input id="phishguard-input" type="file" accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook" style="display:none">
      <div class="phg-row" id="phishguard-fileinfo">Aucun fichier sélectionné pour le moment.</div>
      <div class="phg-row" id="phishguard-status">Prêt pour l’analyse.</div>
      <div class="phg-buttons phg-row">
        <button id="phishguard-open-options" class="phg-primary-btn" type="button">Configurer l’API</button>
        <button id="phishguard-close" type="button">Fermer</button>
      </div>
      <div id="phishguard-result" class="phg-empty">Le résultat d’analyse s’affichera ici après l’envoi du fichier.</div>
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
    const open = panel.style.display !== 'block';
    panel.style.display = open ? 'block' : 'none';
    launcher.setAttribute('aria-expanded', String(open));
  });
  closeBtn.addEventListener('click', () => { panel.style.display = 'none'; launcher.setAttribute('aria-expanded', 'false'); });
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
