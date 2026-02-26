function uniqueSorted(items) {
  return Array.from(new Set((items || []).filter(Boolean))).sort((a, b) => a.localeCompare(b));
}

function scanPageForSensitiveInfo() {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const ipRegex = /\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b/g;
  const keywordRegex = /(password|secret|api[-_]?key|token|internal)/gi;
  const phoneRegex = /(\+[\d\s.-]{7,15})|\b(06[\s.-]?\d{8})\b/g;

  const bodyText = (document.body && document.body.innerText) ? document.body.innerText : '';

  return {
    emails: uniqueSorted(bodyText.match(emailRegex)),
    ips: uniqueSorted(bodyText.match(ipRegex)),
    keywords: uniqueSorted((bodyText.match(keywordRegex) || []).map((x) => x.toLowerCase())),
    phones: uniqueSorted(bodyText.match(phoneRegex)),
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
  const csvRows = ['Category,Value'];
  const addRows = (category, items) => items.forEach((item) => csvRows.push(`${escapeCsv(category)},${escapeCsv(item)}`));
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
    ...data.emails.map((x) => `email:${x}`),
    ...data.ips.map((x) => `ip:${x}`),
    ...data.keywords.map((x) => `keyword:${x}`),
    ...data.phones.map((x) => `phone:${x}`),
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

      const resultText = document.createElement('span');
      resultText.className = 'result-text';
      resultText.textContent = item;

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyToClipboard(item, copyBtn));

      resultItem.appendChild(resultText);
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

        const data = results?.[0]?.result;
        if (!data) {
          showError('No scan data returned from page context.');
          document.getElementById('results').textContent = 'No results.';
          return;
        }

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
