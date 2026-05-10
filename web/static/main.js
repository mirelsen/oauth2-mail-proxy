console.log("mail-bridge UI static ready");

async function fetchJSON(u) {
  const r = await fetch(u, { credentials: 'include' });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function renderDashboard() {
  const el = document.getElementById('dash');
  el.innerHTML = '<p>Se încarcă...</p>';
  try {
    const accounts = await fetchJSON('/api/accounts');
    el.innerHTML = '';
    for (const a of accounts) {
      const status = a.has_token ? (a.expiry ? `token ok (exp: ${a.expiry})` : 'token ok') : 'token lipsă';
      const actions = [
        `<a href="/oauth/start?ref=${encodeURIComponent(a.oauth_ref || a.OAuthRef || '')}&email=${encodeURIComponent(a.email)}">Enroll/Reauth</a>`,
        `<a href="#" data-act="test-imap" data-email="${a.email}">Test IMAP</a>`,
        `<a href="#" data-act="test-smtp" data-email="${a.email}">Test SMTP</a>`
      ].join(' | ');
      const row = document.createElement('div');
      row.className = 'row';
      row.innerHTML = `<div class="card"><div><b>${a.label}</b> — ${a.email} (${a.provider})</div><div>${status}</div><div>${actions}</div></div>`;
      el.appendChild(row);
    }
    el.addEventListener('click', async (ev) => {
      const a = ev.target.closest('a[data-act]');
      if (!a) return;
      ev.preventDefault();
      const act = a.getAttribute('data-act');
      const email = a.getAttribute('data-email');
      if (act === 'test-imap') {
        try {
          const r = await fetch(`/api/test/imap?email=${encodeURIComponent(email)}`, { credentials: 'include' });
          const j = await r.json();
          alert(`INBOX: ${j.count} subiecte\n` + (j.subjects||[]).join('\n'));
        } catch (e) { alert('Eroare IMAP: ' + e); }
      } else if (act === 'test-smtp') {
        try {
          const r = await fetch(`/api/test/smtp?email=${encodeURIComponent(email)}`, { credentials: 'include' });
          const j = await r.json();
          alert('Email de test trimis: ' + (j.ok ? 'OK' : 'FAIL'));
        } catch (e) { alert('Eroare SMTP: ' + e); }
      }
    });
  } catch (e) {
    el.innerHTML = `<p style="color:#f88">Eroare: ${e}</p>`;
  }
}

window.addEventListener('DOMContentLoaded', renderDashboard);

async function initWizard() {
  const sel = document.getElementById('w-provider');
  const btn = document.getElementById('w-create');
  const help = document.getElementById('w-help');
  const providers = await fetchJSON('/api/providers');
  sel.innerHTML = '';
  Object.entries(providers).forEach(([ref, cfg]) => {
    const o = document.createElement('option');
    o.value = ref; o.textContent = `${ref} (${cfg.Provider})`;
    sel.appendChild(o);
  });
  function renderHelp() {
    const ref = sel.value; const p = providers[ref]?.Provider;
    if (p === 'gmail') {
      help.innerHTML = `Gmail: creează OAuth app, scope https://mail.google.com/, Authorization Code, redirect ${providers[ref].RedirectURL}.\nClient legacy: IMAP 127.0.0.1:1143, SMTP 127.0.0.1:1025, user=email, pass=anything.`;
    } else if (p === 'm365') {
      help.innerHTML = `Microsoft 365: scope https://outlook.office365.com/IMAP.AccessAsUser.All https://outlook.office365.com/SMTP.Send offline_access, redirect ${providers[ref].RedirectURL}.\nClient legacy: IMAP 127.0.0.1:1143, SMTP 127.0.0.1:1025, user=email, pass=anything.`;
    } else { help.textContent = ''; }
  }
  sel.addEventListener('change', renderHelp); renderHelp();
  btn.addEventListener('click', async () => {
    const label = document.getElementById('w-label').value.trim();
    const email = document.getElementById('w-email').value.trim();
    const oauth_ref = sel.value; const provider = providers[oauth_ref].Provider;
    if (!label || !email) { alert('Completează label și email'); return; }
    const r = await fetch('/api/accounts/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label, email, provider, oauth_ref }) });
    if (!r.ok) { alert('Eroare: '+await r.text()); return; }
    // deschide enroll
    location.href = `/oauth/start?ref=${encodeURIComponent(oauth_ref)}&email=${encodeURIComponent(email)}`;
  });
}

window.addEventListener('DOMContentLoaded', initWizard);


