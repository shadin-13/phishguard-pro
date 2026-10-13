document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || '';
  document.getElementById('pageUrl').textContent = url || 'No URL';

  document.getElementById('checkBtn').addEventListener('click', async () => {
    if (!url || url.startsWith('chrome://') || url.startsWith('about:')) {
      alert('Cannot scan this page');
      return;
    }
    const btn = document.getElementById('checkBtn');
    const loading = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    btn.disabled = true;
    loading.style.display = 'block';
    resultDiv.style.display = 'none';

    try {
      // Note: User must be logged in on the web app for session cookie,
      // or you can expose a public health/check endpoint.
      // For demo we call the public-style endpoint if available,
      // otherwise show instruction.
      const res = await fetch('http://127.0.0.1:5000/api/url-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        credentials: 'include'
      });

      if (res.status === 401) {
        resultDiv.className = 'threat';
        resultDiv.innerHTML = 'Please login to PhishGuard Pro web app first<br>(http://127.0.0.1:5000)';
        resultDiv.style.display = 'block';
        return;
      }

      const data = await res.json();
      resultDiv.className = data.is_phishing ? 'threat' : 'safe';
      resultDiv.innerHTML = `
        <strong>${data.label}</strong><br>
        Confidence: ${data.confidence}%<br>
        Risk: ${data.risk_score}/100 (${data.threat_level})
      `;
      resultDiv.style.display = 'block';
    } catch (e) {
      resultDiv.className = 'threat';
      resultDiv.innerHTML = 'Cannot reach PhishGuard Pro server.<br>Make sure it is running on localhost:5000';
      resultDiv.style.display = 'block';
    } finally {
      btn.disabled = false;
      loading.style.display = 'none';
    }
  });
});
