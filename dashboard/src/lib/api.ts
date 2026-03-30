import type {
  ServiceSummary,
  ServiceDetail,
  ConnectionSummary,
  ExecuteRequest,
  ExecuteResponse
} from './types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:3000';

class ApiError extends Error {
  constructor(
    public status: number,
    public body: string
  ) {
    super(`API error ${status}: ${body}`);
  }
}

async function request<T>(apiKey: string, method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  if (!res.ok) throw new ApiError(res.status, text);
  return text ? JSON.parse(text) : undefined;
}

export async function listServices(apiKey: string): Promise<ServiceSummary[]> {
  return request(apiKey, 'GET', '/v1/services');
}

export async function getService(apiKey: string, key: string): Promise<ServiceDetail> {
  return request(apiKey, 'GET', `/v1/services/${encodeURIComponent(key)}`);
}

export async function listConnections(apiKey: string): Promise<ConnectionSummary[]> {
  return request(apiKey, 'GET', '/v1/connections');
}

export async function executeAction(
  apiKey: string,
  req: ExecuteRequest
): Promise<ExecuteResponse> {
  return request(apiKey, 'POST', '/v1/actions/execute', req);
}

// JSON syntax highlighter — returns HTML string
export function highlightJson(value: unknown, indent = 0): string {
  const pad = '  '.repeat(indent);
  if (value === null) return `<span class="json-null">null</span>`;
  if (typeof value === 'boolean') return `<span class="json-bool">${value}</span>`;
  if (typeof value === 'number') return `<span class="json-number">${value}</span>`;
  if (typeof value === 'string') {
    const escaped = value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    return `<span class="json-string">"${escaped}"</span>`;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return `<span class="json-bracket">[]</span>`;
    const items = value.map((v) => `${pad}  ${highlightJson(v, indent + 1)}`).join(',\n');
    return `<span class="json-bracket">[</span>\n${items}\n${pad}<span class="json-bracket">]</span>`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return `<span class="json-bracket">{}</span>`;
    const lines = entries
      .map(
        ([k, v]) =>
          `${pad}  <span class="json-key">"${k}"</span>: ${highlightJson(v, indent + 1)}`
      )
      .join(',\n');
    return `<span class="json-bracket">{</span>\n${lines}\n${pad}<span class="json-bracket">}</span>`;
  }
  return String(value);
}

export { ApiError };
