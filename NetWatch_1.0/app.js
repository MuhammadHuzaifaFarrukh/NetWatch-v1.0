// ── CONFIG ────────────────────────────────────────────────────
const API = 'http://localhost:8080';
let allPackets = [];
let pollTimer = null;
let isCapturing = false;

// ── LOG ───────────────────────────────────────────────────────
function log(msg, type = '') {
  const el = document.getElementById('logConsole');
  const now = new Date().toLocaleTimeString('en-GB');
  const div = document.createElement('div');
  div.className = 'log-line ' + type;
  div.textContent = `[${now}] ${msg}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function clearLog() {
  document.getElementById('logConsole').innerHTML = '';
  log('Log cleared.', 'info');
}

// ── STATUS ────────────────────────────────────────────────────
function setStatus(state) {
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  const btnStart = document.getElementById('btnStart');
  const btnStop = document.getElementById('btnStop');

  dot.className = 'status-dot';
  if (state === 'capturing') {
    dot.classList.add('active');
    txt.textContent = 'CAPTURING';
    btnStart.disabled = true;
    btnStop.disabled = false;
    isCapturing = true;
  } else if (state === 'stopped') {
    dot.classList.add('stopped');
    txt.textContent = 'STOPPED';
    btnStart.disabled = false;
    btnStop.disabled = true;
    isCapturing = false;
  } else {
    txt.textContent = 'IDLE';
    btnStart.disabled = false;
    btnStop.disabled = true;
    isCapturing = false;
  }
}

// ── LOAD DEVICES ─────────────────────────────────────────────
async function loadDevices() {
  try {
    const r = await fetch(`${API}/api/devices`);
    const devs = await r.json();
    const sel = document.getElementById('deviceSelect');
    sel.innerHTML = '';
    if (!devs.length) {
      sel.innerHTML = '<option value="">No devices found (run as Admin?)</option>';
      log('No network devices found. Try running as Administrator.', 'error');
      return;
    }
    devs.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.name;
      opt.textContent = d.desc || d.name;
      sel.appendChild(opt);
    });
    log(`Found ${devs.length} network interface(s).`, 'success');
  } catch (e) {
    document.getElementById('deviceSelect').innerHTML =
      '<option value="">Cannot reach backend — is server.exe running?</option>';
    log('Cannot connect to backend on port 8080. Start server.exe first!', 'error');
  }
}

// ── START CAPTURE ────────────────────────────────────────────
async function startCapture() {
  const dev = document.getElementById('deviceSelect').value;
  if (!dev) { log('Please select a network interface first.', 'warn'); return; }

  try {
    const r = await fetch(`${API}/api/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ dev: dev })
    }); const d = await r.json();
    if (d.status === 'started') {
      setStatus('capturing');
      log(`Capture started on: ${dev}`, 'success');
      startPolling();
    } else {
      log('Failed to start: ' + JSON.stringify(d), 'error');
    }
  } catch (e) {
    log('Error starting capture: ' + e.message, 'error');
  }
}

// ── STOP CAPTURE ─────────────────────────────────────────────
async function stopCapture() {
  try {
    await fetch(`${API}/api/stop`);
    setStatus('stopped');
    stopPolling();
    log('Capture stopped.', 'warn');
  } catch (e) {
    log('Error stopping: ' + e.message, 'error');
  }
}

// ── CLEAR DATA ────────────────────────────────────────────────
async function clearData() {
  try {
    await fetch(`${API}/api/clear`);
    allPackets = [];
    renderTable([]);
    updateStats({ total_packets: 0, tcp: 0, udp: 0, icmp: 0, other: 0, avg_size: 0 });
    log('Data cleared.', 'info');
  } catch (e) {
    log('Error clearing: ' + e.message, 'error');
  }
}

// ── POLLING ──────────────────────────────────────────────────
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(fetchData, 1500);
  fetchData();
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function fetchData() {
  try {
    const [pRes, sRes] = await Promise.all([
      fetch(`${API}/api/packets`),
      fetch(`${API}/api/stats`)
    ]);
    allPackets = await pRes.json();
    const stats = await sRes.json();
    updateStats(stats);
    applyFilter();

    // If backend says stopped, update UI
    if (!stats.capturing && isCapturing) {
      setStatus('stopped');
      stopPolling();
      log('Capture ended by backend.', 'warn');
    }
  } catch (e) {
    log('Polling error: ' + e.message, 'error');
    stopPolling();
    setStatus('stopped');
  }
}

// ── UPDATE STATS ─────────────────────────────────────────────
function updateStats(s) {
  document.getElementById('statTotal').textContent = s.total_packets;
  document.getElementById('statTCP').textContent = s.tcp;
  document.getElementById('statUDP').textContent = s.udp;
  document.getElementById('statICMP').textContent = s.icmp;
  document.getElementById('statOther').textContent = s.other;
  document.getElementById('statAvg').textContent = s.avg_size;
}

// ── FILTER ───────────────────────────────────────────────────
function applyFilter() {
  const proto = document.getElementById('fProto').value.toUpperCase();
  const srcIP = document.getElementById('fSrcIP').value.trim();
  const dstIP = document.getElementById('fDstIP').value.trim();
  const service = document.getElementById('fService').value.trim().toUpperCase();

  const filtered = allPackets.filter(p => {
    if (proto && p.protocol.toUpperCase() !== proto) return false;
    if (srcIP && !p.src_ip.includes(srcIP)) return false;
    if (dstIP && !p.dst_ip.includes(dstIP)) return false;
    if (service && !p.service.toUpperCase().includes(service)) return false;
    return true;
  });

  renderTable(filtered);
}

function resetFilter() {
  document.getElementById('fProto').value = '';
  document.getElementById('fSrcIP').value = '';
  document.getElementById('fDstIP').value = '';
  document.getElementById('fService').value = '';
  renderTable(allPackets);
}

// ── RENDER TABLE ─────────────────────────────────────────────
let lastRenderCount = 0;

function renderTable(packets) {
  const tbody = document.getElementById('packetBody');
  document.getElementById('shownCount').textContent = packets.length;
  document.getElementById('totalCount').textContent = allPackets.length;

  if (!packets.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No packets match the current filters.</td></tr>`;
    lastRenderCount = 0;
    return;
  }

  // Only re-render if count changed (performance)
  if (packets.length === lastRenderCount) return;

  // Show latest packets at top (reverse)
  const display = [...packets].reverse().slice(0, 300);

  tbody.innerHTML = display.map((p, i) => {
    const isNew = i < (packets.length - lastRenderCount);
    const svcClass = (p.service === 'Unknown' || p.service === 'N/A')
      ? 'service-unknown' : 'service-badge';
    return `<tr class="${isNew && lastRenderCount > 0 ? 'new-row' : ''}">
      <td>${escHtml(p.time)}</td>
      <td>${escHtml(p.src_ip)}</td>
      <td>${escHtml(p.dst_ip)}</td>
      <td><span class="proto-badge proto-${escHtml(p.protocol)}">${escHtml(p.protocol)}</span></td>
      <td>${p.src_port || '—'}</td>
      <td>${p.dst_port || '—'}</td>
      <td><span class="${svcClass}">${escHtml(p.service)}</span></td>
      <td>${p.packet_size}</td>
    </tr>`;
  }).join('');

  lastRenderCount = packets.length;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── INIT ─────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  setStatus('idle');
  loadDevices();
  log('Ready. Select a network interface and click START.', 'info');
});
