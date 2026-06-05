document.addEventListener('DOMContentLoaded', () => {
  const alertsContainer = document.getElementById('alertsContainer');
  const themeToggle = document.getElementById('themeToggle');
  const searchInput = document.getElementById('searchInput');
  const filterButtons = document.querySelectorAll('.filter-btn');
  
  // Stats DOM
  const valTotal = document.getElementById('valTotal');
  const valCritical = document.getElementById('valCritical');
  const valAnomalies = document.getElementById('valAnomalies');
  const valAgents = document.getElementById('valAgents');

  // Modal DOM
  const alertModal = document.getElementById('alertModal');
  const modalClose = document.getElementById('modalClose');
  const modalSeverityBadge = document.getElementById('modalSeverityBadge');
  const modalEventTitle = document.getElementById('modalEventTitle');
  const modalAgent = document.getElementById('modalAgent');
  const modalIP = document.getElementById('modalIP');
  const modalTimestamp = document.getElementById('modalTimestamp');
  const modalScore = document.getElementById('modalScore');
  const anomalyFeatureSection = document.getElementById('anomalyFeatureSection');
  const modalRawJson = document.getElementById('modalRawJson');
  
  // Modal Features DOM
  const featCpu = document.getElementById('featCpu');
  const featCpuBar = document.getElementById('featCpuBar');
  const featRam = document.getElementById('featRam');
  const featRamBar = document.getElementById('featRamBar');
  const featData = document.getElementById('featData');
  const featDataBar = document.getElementById('featDataBar');
  const featFailed = document.getElementById('featFailed');
  const featFailedBar = document.getElementById('featFailedBar');

  // Modal Buttons DOM
  const actionBan = document.getElementById('actionBan');
  const actionDismiss = document.getElementById('actionDismiss');

  let allAlerts = [];
  let currentFilter = 'all';
  let searchQuery = '';

  // Theme Toggle Logic
  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
  });

  // Search Logic
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    renderAlerts();
  });

  // Filter pills logic
  filterButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      filterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter');
      renderAlerts();
    });
  });

  // Modal close
  modalClose.addEventListener('click', () => {
    alertModal.classList.remove('open');
  });

  window.addEventListener('click', (e) => {
    if (e.target === alertModal) {
      alertModal.classList.remove('open');
    }
  });

  // Action Buttons Mock Actions
  actionDismiss.addEventListener('click', () => {
    alert('Alert dismissed (SOC mock action)');
    alertModal.classList.remove('open');
  });

  actionBan.addEventListener('click', () => {
    const offendingIp = modalIP.textContent;
    alert(`[Active Response] Action dispatched: IP ${offendingIp} is now blocked on edge firewall (Wazuh active ban mock).`);
    alertModal.classList.remove('open');
  });

  // Main polling loop
  async function fetchAlerts() {
    try {
      const res = await fetch('/api/alerts');
      if (!res.ok) throw new Error('API Request Failed');
      const data = await res.json();
      allAlerts = Array.isArray(data) ? data : [];
      updateDashboardStats();
      renderAlerts();
    } catch (err) {
      console.error('Error fetching security alerts:', err);
    }
  }

  // Calculate and update top stats
  function updateDashboardStats() {
    valTotal.textContent = allAlerts.length;

    // Count Critical
    const criticalCount = allAlerts.filter(a => a.severity === 'critical').length;
    valCritical.textContent = criticalCount;

    // Count AI Anomalies
    const anomalyCount = allAlerts.filter(a => isAIAnomaly(a)).length;
    valAnomalies.textContent = anomalyCount;

    // Count unique agents
    const agents = new Set(allAlerts.map(a => a.agent).filter(Boolean));
    valAgents.textContent = agents.size > 0 ? agents.size : 1; // Default to at least 1 (the manager)
  }

  function isAIAnomaly(alert) {
    return (
      (alert.event && alert.event.startsWith('AI ANOMALY:')) || 
      alert.anomaly_score !== undefined || 
      alert.features !== undefined
    );
  }

  // Render alerts grid
  function renderAlerts() {
    const filtered = allAlerts.filter(a => {
      // 1. Severity/Category Filter
      if (currentFilter === 'ai' && !isAIAnomaly(a)) return false;
      if (currentFilter !== 'all' && currentFilter !== 'ai' && a.severity !== currentFilter) return false;

      // 2. Search Query Filter
      if (searchQuery) {
        const text = `${a.agent} ${a.ip} ${a.event} ${a.severity}`.toLowerCase();
        return text.includes(searchQuery);
      }
      return true;
    });

    if (filtered.length === 0) {
      alertsContainer.innerHTML = `
        <div class="empty-state">
          <h3>No events detected</h3>
          <p>The security pipeline is currently quiet. Everything is clear.</p>
        </div>
      `;
      return;
    }

    alertsContainer.innerHTML = '';
    filtered.forEach(alert => {
      const isAI = isAIAnomaly(alert);
      const card = document.createElement('div');
      card.className = `alert-card card-${isAI ? 'ai' : alert.severity}`;

      // Card Header
      const header = document.createElement('div');
      header.className = 'card-header';
      
      const badge = document.createElement('span');
      badge.className = `badge badge-${isAI ? 'ai' : alert.severity}`;
      badge.textContent = isAI ? 'AI ANOMALY' : alert.severity;
      
      const ts = document.createElement('span');
      ts.className = 'card-timestamp';
      ts.textContent = formatTimestamp(alert.timestamp);
      
      header.appendChild(badge);
      header.appendChild(ts);

      // Card Content
      const content = document.createElement('div');
      content.className = 'card-event';
      content.textContent = alert.event;

      // Card Footer Meta
      const meta = document.createElement('div');
      meta.className = 'card-meta';
      
      const host = document.createElement('span');
      host.textContent = `🖥️ ${alert.agent || 'Unknown host'}`;
      
      const ip = document.createElement('span');
      ip.className = 'tech-font';
      ip.textContent = alert.ip || 'Local';

      meta.appendChild(host);
      meta.appendChild(ip);

      card.appendChild(header);
      card.appendChild(content);
      card.appendChild(meta);

      // Card Click Handler
      card.addEventListener('click', () => {
        openModal(alert);
      });

      alertsContainer.appendChild(card);
    });
  }

  function openModal(alert) {
    const isAI = isAIAnomaly(alert);
    
    // Set text details
    modalSeverityBadge.className = `badge badge-${isAI ? 'ai' : alert.severity}`;
    modalSeverityBadge.textContent = isAI ? 'AI ANOMALY' : alert.severity;
    modalEventTitle.textContent = alert.event;
    modalAgent.textContent = alert.agent || 'SIEM Manager';
    modalIP.textContent = alert.ip || 'N/A';
    modalTimestamp.textContent = new Date(alert.timestamp).toLocaleString();
    modalRawJson.textContent = JSON.stringify(alert, null, 2);

    if (isAI) {
      modalScore.textContent = alert.anomaly_score !== undefined ? alert.anomaly_score.toFixed(4) : 'Outlier Detected';
      anomalyFeatureSection.style.display = 'block';

      // Populate features info
      const f = alert.features || {};
      const cpu = f.cpu_utilization !== undefined ? f.cpu_utilization : 0;
      const ram = f.ram_utilization !== undefined ? f.ram_utilization : 0;
      const net = f.data_transmitted_kb !== undefined ? f.data_transmitted_kb : 0;
      const failed = f.failed_attempts_5m !== undefined ? f.failed_attempts_5m : 0;

      // CPU progress
      featCpu.textContent = `${cpu}%`;
      featCpuBar.style.width = `${Math.min(cpu, 100)}%`;
      setProgressBarColor(featCpuBar, cpu);

      // RAM progress
      featRam.textContent = `${ram}%`;
      featRamBar.style.width = `${Math.min(ram, 100)}%`;
      setProgressBarColor(featRamBar, ram);

      // Network Volume progress (Scale arbitrarily: say max 20,000 KB is 100%)
      const netPercent = Math.min((net / 20000) * 100, 100);
      featData.textContent = `${net.toLocaleString()} KB`;
      featDataBar.style.width = `${netPercent}%`;
      setProgressBarColor(featDataBar, netPercent);

      // Failed attempts progress (Scale arbitrarily: 10 attempts is 100%)
      const failedPercent = Math.min((failed / 10) * 100, 100);
      featFailed.textContent = `${failed} failed login attempt(s)`;
      featFailedBar.style.width = `${failedPercent}%`;
      setProgressBarColor(featFailedBar, failedPercent);

    } else {
      modalScore.textContent = 'N/A (Standard rule)';
      anomalyFeatureSection.style.display = 'none';
    }

    alertModal.classList.add('open');
  }

  function setProgressBarColor(bar, value) {
    bar.className = 'progress-bar';
    if (value >= 85) {
      bar.classList.add('bg-red');
    } else if (value >= 50) {
      bar.classList.add('bg-orange');
    } else if (value >= 25) {
      bar.classList.add('bg-blue');
    } else {
      bar.classList.add('bg-purple');
    }
  }

  function formatTimestamp(tsString) {
    try {
      const d = new Date(tsString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch(e) {
      return tsString;
    }
  }

  // Start polling
  fetchAlerts();
  setInterval(fetchAlerts, 2000);
});
