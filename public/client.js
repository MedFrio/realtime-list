// client.js - logique côté client

const els = {
  username: document.getElementById('username'),
  password: document.getElementById('password'),
  btnRegister: document.getElementById('btn-register'),
  btnLogin: document.getElementById('btn-login'),
  btnLogout: document.getElementById('btn-logout'),
  whoami: document.getElementById('whoami'),
  connCount: document.getElementById('conn-count'),
  latency: document.getElementById('latency'),
  presence: document.getElementById('presence'),
  newItem: document.getElementById('new-item'),
  btnAdd: document.getElementById('btn-add'),
  list: document.getElementById('list'),
  logbox: document.getElementById('logbox')
};

let ws = null;
let backoff = 500; // ms
let backoffMax = 8000;
let pingTimer = null;
let lastPingSent = 0;

function log(line) {
  const t = new Date().toISOString().slice(11, 19);
  els.logbox.textContent = `[${t}] ${line}\n` + els.logbox.textContent;
}

function setAuthUI(isAuthed) {
  els.btnLogout.style.display = isAuthed ? 'inline-block' : 'none';
  els.btnLogin.style.display = isAuthed ? 'none' : 'inline-block';
  els.btnRegister.style.display = isAuthed ? 'none' : 'inline-block';
  els.username.style.display = isAuthed ? 'none' : 'inline-block';
  els.password.style.display = isAuthed ? 'none' : 'inline-block';
}

function saveToken(token, username) {
  localStorage.setItem('token', token);
  localStorage.setItem('username', username);
  els.whoami.textContent = `Connecté: ${username}`;
  setAuthUI(true);

  // si le WebSocket est déjà ouvert, renvoyer tout de suite le handshake d'auth
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify({ type: 'auth', token }));
      log('re-auth envoyée après mise à jour du token');
    } catch (e) {
      log('échec re-auth immédiate, on force une reconnexion');
      try { ws.close(); } catch {}
    }
  }
}
function getToken() { return localStorage.getItem('token'); }
function getUsername() { return localStorage.getItem('username'); }

async function api(path, body) {
  const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'erreur api');
  return data;
}

els.btnRegister.onclick = async () => {
  try {
    const data = await api('/api/register', { username: els.username.value.trim(), password: els.password.value });
    saveToken(data.token, data.username);
    connectWS();
    log('inscription ok');
  } catch (e) { log('inscription échouée: ' + e.message); }
};

els.btnLogin.onclick = async () => {
  try {
    const data = await api('/api/login', { username: els.username.value.trim(), password: els.password.value });
    saveToken(data.token, data.username);
    connectWS();
    log('connexion ok');
  } catch (e) { log('connexion échouée: ' + e.message); }
};

els.btnLogout.onclick = async () => {
  const token = getToken();
  // on tente d’invalider côté serveur si possible, sinon ce n’est pas bloquant en local
  try {
    if (token) await api('/api/logout', { token });
  } catch (e) {
    // pas grave en local, on log juste
    log('logout côté serveur non confirmé: ' + e.message);
  }

  // nettoyage local
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  els.whoami.textContent = '';
  setAuthUI(false);

  // fermeture WS et reset UI
  try { if (ws) ws.close(); } catch {}
  ws = null;
  els.connCount.textContent = '0';
  els.presence.textContent = '–';
  els.latency.textContent = '–';
  els.list.innerHTML = '';
  log('déconnexion effectuée');
};

function renderList(items) {
  els.list.innerHTML = '';
  for (const it of items) addListItem(it);
}

function addListItem(it) {
  const li = document.createElement('li');
  li.dataset.id = it.id;
  const left = document.createElement('span');
  left.textContent = it.content;

  const actions = document.createElement('div');
  actions.className = 'actions';

  const btnEdit = document.createElement('button');
  btnEdit.textContent = 'Éditer';
  btnEdit.onclick = () => {
    const current = left.textContent;
    const input = document.createElement('input');
    input.className = 'edit';
    input.value = current;
    const btnSave = document.createElement('button');
    btnSave.textContent = 'OK';
    const btnCancel = document.createElement('button');
    btnCancel.textContent = 'Annuler';

    const restore = () => { actions.replaceChildren(btnEdit, btnDel); left.textContent = current; };
    btnSave.onclick = () => {
      const val = input.value.trim();
      if (val) send({ type: 'edit', id: it.id, content: val });
      restore();
    };
    btnCancel.onclick = restore;

    left.textContent = '';
    left.appendChild(input);
    input.focus();
    actions.replaceChildren(btnSave, btnCancel);
  };

  const btnDel = document.createElement('button');
  btnDel.textContent = 'Supprimer';
  btnDel.onclick = () => {
    if (confirm('Supprimer cet item ?')) send({ type: 'delete', id: it.id });
  };

  actions.append(btnEdit, btnDel);
  li.append(left, actions);
  els.list.appendChild(li);
}

function updateListEdited(id, content) {
  const li = els.list.querySelector(`li[data-id="${id}"]`);
  if (li) li.querySelector('span').textContent = content;
}
function removeListItem(id) {
  const li = els.list.querySelector(`li[data-id="${id}"]`);
  if (li) li.remove();
}

function send(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  } else {
    log('WS non connecté, action ignorée');
  }
}

function connectWS() {
  if (!getToken()) return;
  if (ws && ws.readyState === WebSocket.OPEN) return;

  const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
  ws = new WebSocket(url);

  ws.onopen = () => {
    backoff = 500;
    log('WS ouvert');

    // envoi du token courant dès l’ouverture
    const t = getToken();
    if (t) {
      ws.send(JSON.stringify({ type: 'auth', token: t }));
    } else {
      log('aucun token en localStorage pour le handshake');
    }

    // ping applicatif pour estimer la latence
    if (pingTimer) clearInterval(pingTimer);
    pingTimer = setInterval(() => {
      lastPingSent = Date.now();
      send({ type: 'ping', t: lastPingSent });
    }, 4000);
  };

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }

    if (msg.type === 'snapshot') {
      renderList(msg.items);
      log(`snapshot reçu (${msg.items.length} items)`);
    }
    else if (msg.type === 'hello') {
      els.connCount.textContent = msg.activeConnections;
      if (getUsername()) els.whoami.textContent = `Connecté: ${getUsername()}`;
      setAuthUI(true);
    }
    else if (msg.type === 'presence') {
      els.presence.textContent = msg.users.length.toString();
    }
    else if (msg.type === 'added') {
      addListItem(msg.item);
      log(`ajout #${msg.item.id}`);
    }
    else if (msg.type === 'edited') {
      updateListEdited(msg.id, msg.content);
      log(`édition #${msg.id}`);
    }
    else if (msg.type === 'deleted') {
      removeListItem(msg.id);
      log(`suppression #${msg.id}`);
    }
    else if (msg.type === 'pong') {
      const rtt = Date.now() - (msg.t || lastPingSent);
      els.latency.textContent = rtt.toString();
    }
    else if (msg.type === 'error' && msg.error === 'auth_failed') {
      log('auth_failed, tentative de re-auth…');
      const t = getToken();
      if (t && ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'auth', token: t }));
          log('re-auth renvoyée avec le token courant');
        } catch {
          try { ws.close(); } catch {}
        }
      } else {
        try { ws.close(); } catch {}
      }
    }
    else if (msg.type === 'error') {
      log('erreur: ' + msg.error);
    }
  };

  ws.onclose = () => {
    log('WS fermé, tentative de reconnexion…');
    els.connCount.textContent = '0';
    if (pingTimer) clearInterval(pingTimer);
    setTimeout(connectWS, backoff + Math.floor(Math.random() * 250)); // jitter
    backoff = Math.min(backoff * 2, backoffMax);
  };

  ws.onerror = () => {
    log('WS erreur');
  };
}

// Ajout d’un item
els.btnAdd.onclick = () => {
  const val = els.newItem.value.trim();
  if (!val) return;
  send({ type: 'add', content: val });
  els.newItem.value = '';
};
els.newItem.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') els.btnAdd.click();
});

// Auto-init UI
if (getToken()) {
  els.whoami.textContent = `Connecté: ${getUsername() || ''}`.trim();
  setAuthUI(true);
  connectWS();
} else {
  setAuthUI(false);
}
