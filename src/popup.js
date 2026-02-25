// Function to scan the page for sensitive information
function scanPageForSensitiveInfo() {
  try {
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const ipRegex = /\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b/g;
    const keywordRegex = /(password|secret|api[-_]?key|token|internal)/gi;
    const phoneRegex = /(\+[\d\s.-]{7,15})|\b(06[\s.-]?\d{8})\b/g;

    const bodyText = document.body.innerText;

    const foundEmails = bodyText.match(emailRegex);
    const foundIPs = bodyText.match(ipRegex);
    const foundKeywords = bodyText.match(keywordRegex);
    const foundPhones = bodyText.match(phoneRegex);
    
    return {
      emails: foundEmails || [],
      ips: foundIPs || [],
      keywords: foundKeywords || [],
      phones: foundPhones || [],  // Fixed missing comma
    };
  } catch (error) {
    console.error('Error scanning page for sensitive information:', error);
    alert('An error occurred while scanning the page.');
    return {
      emails: [],
      ips: [],
      keywords: [],
      phones: [],
    };
  }
}

// Function to copy text to clipboard with feedback
function copyToClipboard(text, button) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.textContent;
    button.textContent = 'Copied!';
    button.style.backgroundColor = '#28a745';  // Change to green
    setTimeout(() => {
      button.textContent = originalText;
      button.style.backgroundColor = '';  // Reset color
    }, 2000);  // Reset after 2 seconds
  });
}

// Function to export data to CSV
function exportToCSV(data) {
  const csvRows = [];
  const headers = ['Category', 'Value'];
  csvRows.push(headers.join(','));

  const addRow = (category, items) => {
    items.forEach(item => {
      csvRows.push(`"${category}","${item}"`);
    });
  };

  addRow('Emails', data.emails);
  addRow('IP Addresses', data.ips);
  addRow('Keywords', data.keywords);
  addRow('Phone Numbers', data.phones);

  const csvContent = csvRows.join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.setAttribute('href', url);
  a.setAttribute('download', 'sensitive_info.csv');
  a.click();
}

// Automatically execute the scan when the popup loads
chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
  chrome.scripting.executeScript({
    target: {tabId: tabs[0].id},
    function: scanPageForSensitiveInfo
  }, (results) => {
    const resultElement = document.getElementById('results');
    const data = results[0].result;

    // Clear the existing content
    resultElement.innerHTML = '';

    const displayResults = (title, items) => {
      const titleElement = document.createElement('h4');
      titleElement.textContent = `${title} (${items.length})`;  // Show count in title
      resultElement.appendChild(titleElement);

      if (items.length === 0) {
        const noFinding = document.createElement('div');
        noFinding.textContent = 'No findings';
        resultElement.appendChild(noFinding);
      } else {
        items.forEach(item => {
          const resultItem = document.createElement('div');
          resultItem.className = 'result-item';

          const resultText = document.createElement('span');
          resultText.textContent = item;

          const copyBtn = document.createElement('button');
          copyBtn.className = 'copy-btn';
          copyBtn.textContent = 'Copy';
          copyBtn.addEventListener('click', () => copyToClipboard(item, copyBtn));

          resultItem.appendChild(resultText);
          resultItem.appendChild(copyBtn);
          resultElement.appendChild(resultItem);
        });
      }
    };

    displayResults('Emails', data.emails);
    displayResults('IP Addresses', data.ips);
    displayResults('Keywords', data.keywords);
    displayResults('Phone Numbers', data.phones);

    // Add the Export All button with improved styling and placement
    const exportBtnContainer = document.createElement('div');
    exportBtnContainer.style.marginTop = '20px';  // Add some space above the button
    exportBtnContainer.style.textAlign = 'center';  // Center the button

    const exportBtn = document.createElement('button');
    exportBtn.textContent = 'Export All to CSV';
    exportBtn.style.padding = '10px 20px';
    exportBtn.style.backgroundColor = '#007bff';
    exportBtn.style.color = '#fff';
    exportBtn.style.border = 'none';
    exportBtn.style.borderRadius = '5px';
    exportBtn.style.cursor = 'pointer';
    exportBtn.addEventListener('click', () => exportToCSV(data));

    exportBtnContainer.appendChild(exportBtn);
    resultElement.appendChild(exportBtnContainer);
  });
});
