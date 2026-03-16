function decodeSnippet(text) {
  const value = String(text || '');
  // Decode URL-encoded snippets safely for analyst readability.
  try {
    return decodeURIComponent(value.replace(/%(?![0-9A-Fa-f]{2})/g, '%25'));
  } catch {
    return value;
  }
}

function riskRank(level) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  return rank[String(level || 'unknown').toLowerCase()] ?? 0;
}

function sortFindings(items) {
  return [...(items || [])].sort((a, b) => {
    const r = riskRank(b.risk_level) - riskRank(a.risk_level);
    if (r !== 0) return r;
    return String(a.value || '').localeCompare(String(b.value || ''));
  });
}

function scanPageForSensitiveInfo() {
  try {
    const riskRankLocal = (level) => {
      const rank = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
      return rank[String(level || 'unknown').toLowerCase()] ?? 0;
    };

    const sortFindingsLocal = (items) => {
      return [...(items || [])].sort((a, b) => {
        const r = riskRankLocal(b.risk_level) - riskRankLocal(a.risk_level);
        if (r !== 0) return r;
        return String(a.value || '').localeCompare(String(b.value || ''));
      });
    };

    const collectWithSnippetsLocal = (text, regex, category, riskLevel, normaliser) => {
      const out = [];
      const seen = new Set();
      let m;
      while ((m = regex.exec(text)) !== null) {
        const raw = m[0];
        const value = normaliser ? normaliser(raw) : raw;
        if (!value || seen.has(value)) continue;
        seen.add(value);

        const start = Math.max(0, m.index - 40);
        const end = Math.min(text.length, m.index + raw.length + 40);
        const snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();

        out.push({ category, value, risk_level: riskLevel, snippet, badge: '' });
      }
      return out;
    };

    const bodyTextRaw = (document.body && document.body.innerText) ? document.body.innerText : '';

    // Ignore common non-web schemes to reduce noisy context findings.
    const bodyText = bodyTextRaw
      .replace(/javascript:[^\s)]+/gi, ' ')
      .replace(/data:[^\s)]+/gi, ' ')
      .replace(/mailto:[^\s)]+/gi, ' ')
      .replace(/tel:[^\s)]+/gi, ' ');

    const scanners = [
      {
        category: 'email',
        regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        risk: 'high',
        normaliser: (v) => v.toLowerCase(),
      },
      {
        category: 'ip',
        regex: /\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b/g,
        risk: 'medium',
      },
      {
        category: 'phone',
        regex: /(\+[\d\s.-]{7,15})|\b(06[\s.-]?\d{8})\b/g,
        risk: 'medium',
        normaliser: (v) => v.trim(),
      },
      {
        category: 'keyword',
        regex: /(api[-_ ]?key|secret[-_ ]?key|private[-_ ]?key|authorization\s*:\s*bearer|bearer\s+[a-z0-9\-_.]+|passwd|password)/gi,
        risk: 'high',
        normaliser: (v) => v.toLowerCase(),
      },
      {
        category: 'keyword',
        regex: /(token|secret|credential|auth\s?token)/gi,
        risk: 'medium',
        normaliser: (v) => v.toLowerCase(),
      },
      {
        category: 'keyword',
        regex: /(internal)/gi,
        risk: 'low',
        normaliser: (v) => v.toLowerCase(),
      },
    ];

    const findings = [];
    scanners.forEach((scanner) => {
      findings.push(...collectWithSnippetsLocal(bodyText, scanner.regex, scanner.category, scanner.risk, scanner.normaliser));
    });

    // Clean common low-value addresses.
    const filtered = findings.filter((f) => {
      if (f.category !== 'email') return true;
      const v = String(f.value || '');
      if (v.endsWith('@example.com')) return false;
      if (v.startsWith('noreply@')) return false;
      return true;
    });

    // Special risk logic: IMDS endpoint is critical cloud metadata exposure.
    filtered.forEach((f) => {
      if (f.category === 'ip' && f.value === '169.254.169.254') {
        f.risk_level = 'critical';
        f.badge = 'Cloud Metadata';
      }
    });

    // Keyword weighting for API key and credential with assignment operators.
    filtered.forEach((f) => {
      if (f.category !== 'keyword') return;
      const value = String(f.value || '').toLowerCase();
      const snippet = String(f.snippet || '');
      const hasAssignment = /[:=]/.test(snippet);
      if (/(api[-_ ]?key|credential)/i.test(value)) {
        f.risk_level = hasAssignment ? 'high' : 'medium';
      }
    });

    // Deduplicate keywords by value, keeping highest risk finding.
    const dedupeByValueKeepHighest = (items) => {
      const map = new Map();
      items.forEach((item) => {
        const key = String(item.value || '');
        const existing = map.get(key);
        if (!existing || riskRankLocal(item.risk_level) > riskRankLocal(existing.risk_level)) {
          map.set(key, item);
        }
      });
      return Array.from(map.values());
    };

    const emails = sortFindingsLocal(filtered.filter((x) => x.category === 'email'));
    const ips = sortFindingsLocal(filtered.filter((x) => x.category === 'ip'));
    const phones = sortFindingsLocal(filtered.filter((x) => x.category === 'phone'));
    const keywords = sortFindingsLocal(dedupeByValueKeepHighest(filtered.filter((x) => x.category === 'keyword')));

    return {
      emails,
      ips,
      keywords,
      phones,
      _scan_error: null,
    };
  } catch (e) {
    return {
      emails: [],
      ips: [],
      keywords: [],
      phones: [],
      _scan_error: String(e && e.message ? e.message : e),
    };
  }
}

function showError(msg) {
  document.getElementById('error').textContent = msg;
}

async function writeClipboardSafe(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fallback below
    }
  }

  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.focus();
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    return !!ok;
  } catch {
    return false;
  }
}

async function copyToClipboard(text, button) {
  const originalText = button.textContent;
  const ok = await writeClipboardSafe(text);

  if (ok) {
    button.textContent = 'Done';
    button.style.backgroundColor = '#2e7d32';
    button.style.color = '#fff';
  } else {
    button.textContent = 'Fail';
    button.style.backgroundColor = '#b00020';
    button.style.color = '#fff';
  }

  setTimeout(() => {
    button.textContent = originalText;
    button.style.backgroundColor = '';
    button.style.color = '';
  }, 900);
}

function escapeCsv(value) {
  const s = String(value ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function download(name, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function exportToCSV(data) {
  const csvRows = ['Category,Value,RiskLevel,Snippet,Badge'];
  const addRows = (category, items) => items.forEach((item) => csvRows.push([
    escapeCsv(category),
    escapeCsv(item.value),
    escapeCsv(item.risk_level || ''),
    escapeCsv(decodeSnippet(item.snippet || '')),
    escapeCsv(item.badge || ''),
  ].join(',')));
  addRows('Emails', data.emails);
  addRows('IP Addresses', data.ips);
  addRows('Keywords', data.keywords);
  addRows('Phone Numbers', data.phones);
  download('sensitive_info.csv', `${csvRows.join('\n')}\n`, 'text/csv');
}

function exportToJSON(data) {
  const normalised = {
    ...data,
    emails: (data.emails || []).map((x) => ({ ...x, snippet: decodeSnippet(x.snippet) })),
    ips: (data.ips || []).map((x) => ({ ...x, snippet: decodeSnippet(x.snippet) })),
    keywords: (data.keywords || []).map((x) => ({ ...x, snippet: decodeSnippet(x.snippet) })),
    phones: (data.phones || []).map((x) => ({ ...x, snippet: decodeSnippet(x.snippet) })),
  };
  download('sensitive_info.json', `${JSON.stringify(normalised, null, 2)}\n`, 'application/json');
}

function allItems(data) {
  return [
    ...data.emails.map((x) => `email:${x.value}`),
    ...data.ips.map((x) => `ip:${x.value}`),
    ...data.keywords.map((x) => `keyword:${x.value}`),
    ...data.phones.map((x) => `phone:${x.value}`),
  ].join('\n');
}

function renderResults(data) {
  const resultElement = document.getElementById('results');
  resultElement.innerHTML = '';

  const headerIcon = {
    'Emails': '✉',
    'IP Addresses': '🌐',
    'Keywords': '🔎',
    'Phone Numbers': '☎',
  };

  const copySvg = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 1H6a2 2 0 0 0-2 2v12h2V3h10V1zm3 4H10a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H10V7h9v14z"/></svg>';

  const displayResults = (title, items) => {
    const card = document.createElement('div');
    card.className = 'category-card';

    const header = document.createElement('div');
    header.className = 'category-header';

    const icon = document.createElement('span');
    icon.className = 'category-icon';
    icon.textContent = headerIcon[title] || '•';

    const label = document.createElement('span');
    label.textContent = `${title} (${items.length})`;

    header.appendChild(icon);
    header.appendChild(label);
    card.appendChild(header);

    if (items.length === 0) {
      const noFinding = document.createElement('div');
      noFinding.className = 'empty-state';
      noFinding.textContent = 'No findings';
      card.appendChild(noFinding);
      resultElement.appendChild(card);
      return;
    }

    items.forEach((item) => {
      const resultItem = document.createElement('div');
      resultItem.className = 'result-item';

      const block = document.createElement('div');
      block.className = 'result-block';

      const resultText = document.createElement('span');
      resultText.className = 'result-text';
      resultText.textContent = item.value;

      const meta = document.createElement('div');
      meta.className = 'result-meta';

      const risk = (item.risk_level || 'unknown').toLowerCase();
      const riskPill = document.createElement('span');
      riskPill.className = `confidence-pill confidence-${risk}`;
      riskPill.textContent = risk;

      meta.appendChild(riskPill);

      if (item.badge) {
        const badge = document.createElement('span');
        badge.className = 'finding-badge';
        badge.textContent = item.badge;
        meta.appendChild(badge);
      }

      const snippet = document.createElement('span');
      snippet.textContent = ` ${decodeSnippet(item.snippet || '')}`;
      meta.appendChild(snippet);

      block.appendChild(resultText);
      block.appendChild(meta);

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.innerHTML = copySvg;
      copyBtn.title = 'Copy value';
      copyBtn.setAttribute('aria-label', `Copy ${item.value}`);
      copyBtn.addEventListener('click', () => copyToClipboard(item.value, copyBtn));

      resultItem.appendChild(block);
      resultItem.appendChild(copyBtn);
      card.appendChild(resultItem);
    });

    resultElement.appendChild(card);
  };

  displayResults('Emails', data.emails);
  displayResults('IP Addresses', data.ips);
  displayResults('Keywords', data.keywords);
  displayResults('Phone Numbers', data.phones);
}

function isScriptableUrl(url) {
  if (!url) return false;
  const blockedPrefixes = [
    'chrome://',
    'chrome-extension://',
    'devtools://',
    'edge://',
    'about:',
    'view-source:',
  ];
  if (blockedPrefixes.some((p) => url.startsWith(p))) return false;
  if (url.includes('chromewebstore.google.com') || url.includes('chrome.google.com/webstore')) return false;
  return /^https?:\/\//i.test(url);
}

document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs?.[0];
    const tabId = tab?.id;
    const tabUrl = tab?.url || '';

    if (!tabId) {
      showError('No active tab available.');
      return;
    }

    if (!isScriptableUrl(tabUrl)) {
      showError('Scanning is blocked on this page type. Open a normal website tab and try again.');
      document.getElementById('results').textContent = 'No results.';
      return;
    }

    chrome.scripting.executeScript(
      {
        target: { tabId },
        func: scanPageForSensitiveInfo,
      },
      (results) => {
        if (chrome.runtime.lastError) {
          showError(`Scan blocked on this page: ${chrome.runtime.lastError.message}`);
          document.getElementById('results').textContent = 'No results.';
          return;
        }

        if (!Array.isArray(results) || !results[0]) {
          showError('No scan data returned from page context.');
          document.getElementById('results').textContent = 'No results.';
          return;
        }

        const data = results[0].result || { emails: [], ips: [], keywords: [], phones: [], _scan_error: 'empty_result' };

        if (data._scan_error) {
          showError(`Page scan error: ${data._scan_error}`);
        }

        renderResults(data);

        document.getElementById('copyAllBtn').onclick = async () => {
          const btn = document.getElementById('copyAllBtn');
          const original = btn.textContent;
          const ok = await writeClipboardSafe(allItems(data));
          btn.textContent = ok ? 'Copied' : 'Failed';
          setTimeout(() => { btn.textContent = original; }, 900);
        };
        document.getElementById('exportCsvBtn').onclick = () => exportToCSV(data);
        document.getElementById('exportJsonBtn').onclick = () => exportToJSON(data);
      }
    );
  });
});
