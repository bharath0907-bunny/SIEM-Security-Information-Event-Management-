// frontend/app.js
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('alertsContainer');
  const themeBtn = document.getElementById('themeToggle');

  // Theme toggle
  themeBtn.addEventListener('click', () => {
    document.body.classList.toggle('dark');
    const mode = document.body.classList.contains('dark') ? 'Dark' : 'Light';
    themeBtn.textContent = `Toggle ${mode}`;
  });

  // Fetch alerts periodically
  async function fetchAlerts() {
    try {
      const resp = await fetch('/api/alerts');
      if (!resp.ok) throw new Error('Network response was not ok');
      const alerts = await resp.json();
      renderAlerts(alerts);
    } catch (e) {
      console.error('Failed to fetch alerts:', e);
    }
  }

  function renderAlerts(alerts) {
    container.innerHTML = '';
    alerts.forEach(alert => {
      const card = document.createElement('div');
      card.className = `alert-card ${severityClass(alert.severity)}`;
      const title = document.createElement('h3');
      title.textContent = `${alert.severity.toUpperCase()} – ${alert.agent}`;
      const details = document.createElement('p');
      details.textContent = `IP: ${alert.ip} | Event: ${alert.event}`;
      const ts = document.createElement('p');
      ts.textContent = `Timestamp: ${new Date(alert.timestamp).toLocaleString()}`;
      card.appendChild(title);
      card.appendChild(details);
      card.appendChild(ts);
      container.appendChild(card);
    });
  }

  function severityClass(sev) {
    switch (sev.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return '';
    }
  }

  // Initial fetch + interval
  fetchAlerts();
  setInterval(fetchAlerts, 3000);
});
