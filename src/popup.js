function uniqueSorted(items) {
  return Array.from(new Set((items || []).filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function collectWithSnippets(text, regex, category, confidence, normaliser) {
  const out = [];
  const seen = new Set();
  let m;
  while ((m = regex.exec(text)) !== null) {
    const raw = m[0];
    const value = normaliser ? normaliser(raw) : raw;
    if (!value || seen.has(value)) continue;
    seen.add(value);

    const start = Math.max(0, m.index - 30);
    const end = Math.min(text.length, m.index + raw.length + 30);
    const snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();

    out.push({ category, value, confidence, snippet });
  }
  return out.sort((a, b) => a.value.localeCompare(b.value));
}

function scanPageForSensitiveInfo() {
  const bodyText = (document.body && document.body.innerText) ? document.body.innerText : '';

  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const ipRegex = /\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b/g;
  const phoneRegex = /(\+[\d\s.-]{7,15})|\b(06[\s.-]?\d{8})\b/g;

  const highKeywordRegex = /(api[-_ ]?key|secret[-_ ]?key|private[-_ ]?key|authorization\s*:\s*bearer|bearer\s+[a-z0-9\-_.]+|passwd|password)/gi;
  const mediumKeywordRegex = /(token|secret|credential|auth\s?token)/gi;
  const lowKeywordRegex = /(internal)/gi;

  const emails = collectWithSnippets(
    bodyText,
    emailRegex,
    'email',
    'high',
    (v) => v.toLowerCase()
  ).filter((x) => !x.value.endsWith('@example.com') && !x.value.startsWith('noreply@'));

  const ips = collectWithSnippets(bodyText, ipRegex, 'ip', 'medium');
  const phones = collectWithSnippets(bodyText, phoneRegex, 'phone', 'medium', (v) => v.trim());

  const keywords = [
    ...collectWithSnippets(bodyText, highKeywordRegex, 'keyword', 'high', (v) => v.toLowerCase()),
    ...collectWithSnippets(bodyText, mediumKeywordRegex, 'keyword', 'medium', (v) => v.toLowerCase()),
    ...collectWithSnippets(bodyText, lowKeywordRegex, 'keyword', 'low', (v) => v.toLowerCase()),
  ];

  const keywordMap = new Map();
  for (const k of keywords) {
    const existing = keywordMap.get(k.value);
    if (!existing) {
      keywordMap.set(k.value, k);
      continue;
    }
    const rank = { high: 3, medium: 2, low: 1 };
    if (rank[k.confidence] > rank[existing.confidence]) {
      keywordMap.set(k.value, k);
    }
  }

  return {
    emails,
    ips,
    keywords: Array.from(keywordMap.values()).sort((a, b) => a.value.localeCompare(b.value)),
    phones,
  };
}

function showError(msg) {
  document.getElementById('error').textContent = msg;
}

function copyToClipboard(text, button) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.textContent;
    button.textContent = 'Copied!';
    button.style.backgroundColor = '#28a745';
    setTimeout(() => {
      button.textContent = originalText;
      button.style.backgroundColor = '';
    }, 1200);
  }).catch((err) => {
    console.error('Clipboard failed:', err);
  });
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
  const csvRows = ['Category,Value,Confidence,Snippet'];
  const addRows = (category, items) => items.forEach((item) => csvRows.push([
    escapeCsv(category),
    escapeCsv(item.value),
    escapeCsv(item.confidence || ''),
    escapeCsv(item.snippet || ''),
  ].join(',')));
  addRows('Emails', data.emails);
  addRows('IP Addresses', data.ips);
  addRows('Keywords', data.keywords);
  addRows('Phone Numbers', data.phones);
  download('sensitive_info.csv', `${csvRows.join('\n')}\n`, 'text/csv');
}

function exportToJSON(data) {
  download('sensitive_info.json', `${JSON.stringify(data, null, 2)}\n`, 'application/json');
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

  const displayResults = (title, items) => {
    const titleElement = document.createElement('h4');
    titleElement.textContent = `${title} (${items.length})`;
    resultElement.appendChild(titleElement);

    if (items.length === 0) {
      const noFinding = document.createElement('div');
      noFinding.textContent = 'No findings';
      resultElement.appendChild(noFinding);
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
      meta.textContent = `confidence=${item.confidence || 'unknown'} | ${item.snippet || ''}`;

      block.appendChild(resultText);
      block.appendChild(meta);

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyToClipboard(item.value, copyBtn));

      resultItem.appendChild(block);
      resultItem.appendChild(copyBtn);
      resultElement.appendChild(resultItem);
    });
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
  // Chrome Web Store and extension gallery pages are blocked from scripting.
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

        if (!Array.isArray(results) || !results[0] || !results[0].result) {
          showError('No scan data returned from page context.');
          document.getElementById('results').textContent = 'No results.';
          return;
        }

        const data = results[0].result;

        renderResults(data);

        document.getElementById('copyAllBtn').onclick = () => {
          navigator.clipboard.writeText(allItems(data)).catch((err) => console.error(err));
        };
        document.getElementById('exportCsvBtn').onclick = () => exportToCSV(data);
        document.getElementById('exportJsonBtn').onclick = () => exportToJSON(data);
      }
    );
  });
});
