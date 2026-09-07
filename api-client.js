const FMODAS_API = location.protocol === 'file:' ? 'http://localhost:3000' : '';
let fmodasApiOnline = false;
async function apiRequest(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetch(`${FMODAS_API}${path}`, { credentials: 'include', ...options, signal: controller.signal });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'Erro na API FMODAS');
    fmodasApiOnline = true;
    return body;
  } finally { clearTimeout(timer); }
}
async function apiForm(path, formData) { return apiRequest(path, { method: 'POST', body: formData }); }
async function apiJson(path, body, method = 'POST') { return apiRequest(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
async function tryApi(path, options) { try { return await apiRequest(path, options); } catch { return null; } }
