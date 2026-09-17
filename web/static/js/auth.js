/**
 * auth.js
 * Gerencia o token JWT no navegador (localStorage), login, logout e
 * a proteção das páginas que exigem usuário autenticado.
 *
 * Usa localStorage (não cookie) de propósito: como o front-end é
 * servido pelo mesmo FastAPI mas consome a API via fetch, isso evita
 * lidar com CSRF de cookie — o token vai manualmente no header
 * Authorization de cada chamada.
 */

const NG_TOKEN_KEY = "netguard_token";
const NG_USER_KEY = "netguard_user";

function ngGetToken() {
  return localStorage.getItem(NG_TOKEN_KEY);
}

function ngSetSession(token, user) {
  localStorage.setItem(NG_TOKEN_KEY, token);
  localStorage.setItem(NG_USER_KEY, JSON.stringify(user));
}

function ngClearSession() {
  localStorage.removeItem(NG_TOKEN_KEY);
  localStorage.removeItem(NG_USER_KEY);
}

function ngGetUser() {
  const raw = localStorage.getItem(NG_USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

/** Redireciona para o login se não houver token — chame no topo de páginas protegidas. */
function ngRequireAuth() {
  if (!ngGetToken()) {
    window.location.href = "/login";
  }
}

/** Wrapper de fetch que já injeta o header de autenticação e trata token expirado/inválido. */
async function ngFetch(url, options = {}) {
  const token = ngGetToken();
  const headers = Object.assign({}, options.headers, {
    Authorization: `Bearer ${token}`,
  });

  const response = await fetch(url, Object.assign({}, options, { headers }));

  if (response.status === 401) {
    ngClearSession();
    window.location.href = "/login";
    throw new Error("Sessão expirada");
  }

  return response;
}

function ngLogout() {
  ngClearSession();
  window.location.href = "/login";
}

/** Preenche o chip de usuário na sidebar, se existir na página. */
function ngRenderUserChip() {
  const el = document.getElementById("ng-user-chip-name");
  const user = ngGetUser();
  if (el && user) {
    el.textContent = user.username;
  }
}

document.addEventListener("DOMContentLoaded", ngRenderUserChip);
