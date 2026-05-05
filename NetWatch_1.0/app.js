const API = 'http://localhost:8080';
let allPackets = [];
let pollTimer = null;
let isCapturing = false;

// ── PAGINATION ────────────────────────────────────────────────
const PAGE_SIZE = 500;
let currentPage = 1;
let filteredPackets = [];

// ── VALID SERVICES ────────────────────────────────────────────
const VALID_SERVICES = new Set([
  'HTTP', 'HTTPS', 'FTP', 'FTPS', 'SSH', 'TELNET', 'SMTP', 'DNS', 'DHCP', 'POP3',
  'IMAP', 'SNMP', 'LDAP', 'LDAPS', 'RDP', 'NTP', 'TFTP', 'MYSQL', 'POSTGRES',
  'MSSQL', 'MONGODB', 'REDIS', 'ELASTICSEARCH', 'KAFKA', 'AMQP', 'MQTT', 'SIP',
  'RTP', 'RTSP', 'SMB', 'NETBIOS', 'KERBEROS', 'RADIUS', 'BGP', 'OSPF', 'IGMP',
  'IRC', 'XMPP', 'SYSLOG', 'IPSEC', 'L2TP', 'PPTP', 'GRE', 'ICMP', 'ARP',
  'HTTP2', 'HTTP3', 'QUIC', 'COAP', 'MDNS', 'LLMNR', 'SSDP', 'UPNP', 'UNKNOWN', 'N/A'
]);

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

// ── INPUT VALIDATION ──────────────────────────────────────────
function validateIPField(input) {
  const val = input.value.trim();
  if (val === '') {
    input.classList.remove('input-error', 'input-ok');
    return true;
  }
  // Allow partial IPs while typing — only flag clearly wrong chars
  const valid = /^[\d.]*$/.test(val);
  if (!valid) {
    input.classList.add('input-error');
    input.classList.remove('input-ok');
    return false;
  } else {
    input.classList.remove('input-error');
    input.classList.add('input-ok');
    return true;
  }
}

function validateServiceField(input) {
  const val = input.value.trim().toUpperCase();
  if (val === '') {
    input.classList.remove('input-error', 'input-ok');
    return true;
  }
  // Valid if it matches any known service (partial prefix match while typing)
  const isValid = [...VALID_SERVICES].some(s => s.startsWith(val));
  if (!isValid) {
    input.classList.add('input-error');
    input.classList.remove('input-ok');
    return false;
  } else {
    input.classList.remove('input-error');
    input.classList.add('input-ok');
    return true;
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
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ dev: dev })
    });
    const d = await r.json();
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
    currentPage = 1;
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
  // Validate before applying
  const srcInput = document.getElementById('fSrcIP');
  const dstInput = document.getElementById('fDstIP');
  const svcInput = document.getElementById('fService');
  validateIPField(srcInput);
  validateIPField(dstInput);
  validateServiceField(svcInput);

  const proto = document.getElementById('fProto').value.toUpperCase();
  const srcIP = srcInput.value.trim();
  const dstIP = dstInput.value.trim();
  const service = svcInput.value.trim().toUpperCase();

  filteredPackets = allPackets.filter(p => {
    if (proto && p.protocol.toUpperCase() !== proto) return false;
    if (srcIP && !p.src_ip.includes(srcIP)) return false;
    if (dstIP && !p.dst_ip.includes(dstIP)) return false;
    if (service && !p.service.toUpperCase().includes(service)) return false;
    return true;
  });

  currentPage = 1;
  renderTable(filteredPackets);
}

function resetFilter() {
  document.getElementById('fProto').value = '';
  const srcInput = document.getElementById('fSrcIP');
  const dstInput = document.getElementById('fDstIP');
  const svcInput = document.getElementById('fService');
  srcInput.value = '';
  dstInput.value = '';
  svcInput.value = '';
  srcInput.classList.remove('input-error', 'input-ok');
  dstInput.classList.remove('input-error', 'input-ok');
  svcInput.classList.remove('input-error', 'input-ok');
  currentPage = 1;
  filteredPackets = allPackets;
  renderTable(filteredPackets);
}

// ── PAGINATION ────────────────────────────────────────────────
function goToPage(page) {
  const totalPages = Math.max(1, Math.ceil(filteredPackets.length / PAGE_SIZE));
  currentPage = Math.max(1, Math.min(page, totalPages));
  renderTable(filteredPackets);
}

// ── RENDER TABLE ─────────────────────────────────────────────
let lastRenderCount = 0;

function renderTable(packets) {
  const tbody = document.getElementById('packetBody');
  const totalPages = Math.max(1, Math.ceil(packets.length / PAGE_SIZE));

  document.getElementById('shownCount').textContent = packets.length;
  document.getElementById('totalCount').textContent = allPackets.length;

  // Update pagination controls
  renderPagination(totalPages);

  if (!packets.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No packets match the current filters.</td></tr>`;
    lastRenderCount = 0;
    return;
  }

  // Paginate — show latest first (reverse), then slice current page
  const reversed = [...packets].reverse();
  const start = (currentPage - 1) * PAGE_SIZE;
  const pagePackets = reversed.slice(start, start + PAGE_SIZE);

  tbody.innerHTML = pagePackets.map((p, i) => {
    const isNew = currentPage === 1 && i < (packets.length - lastRenderCount);
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

function renderPagination(totalPages) {
  const container = document.getElementById('paginationControls');
  if (!container) return;

  if (totalPages <= 1) {
    container.innerHTML = '';
    return;
  }

  let html = `<div class="pagination">`;
  html += `<button class="page-btn" onclick="goToPage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>◀ PREV</button>`;

  // Show page buttons — window of 5 around current
  const range = 2;
  for (let i = 1; i <= totalPages; i++) {
    if (i === 1 || i === totalPages || (i >= currentPage - range && i <= currentPage + range)) {
      html += `<button class="page-btn ${i === currentPage ? 'page-active' : ''}" onclick="goToPage(${i})">${i}</button>`;
    } else if (i === currentPage - range - 1 || i === currentPage + range + 1) {
      html += `<span class="page-ellipsis">…</span>`;
    }
  }

  html += `<button class="page-btn" onclick="goToPage(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>NEXT ▶</button>`;
  html += `<span class="page-info">Page ${currentPage} of ${totalPages}</span>`;
  html += `</div>`;

  container.innerHTML = html;
}

// ── CSV IMPORT ────────────────────────────────────────────────
function importCSV() {
  document.getElementById('csvFileInput').click();
}

function handleCSVImport(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function (e) {
    const text = e.target.result;
    const lines = text.trim().split('\n');
    if (lines.length < 2) {
      log('CSV file is empty or has no data rows.', 'error');
      return;
    }

    // Parse header
    const header = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, '').toLowerCase());
    const colMap = {
      time: header.indexOf('time'),
      src_ip: header.indexOf('src_ip') !== -1 ? header.indexOf('src_ip') : header.indexOf('source ip'),
      dst_ip: header.indexOf('dst_ip') !== -1 ? header.indexOf('dst_ip') : header.indexOf('destination ip'),
      protocol: header.indexOf('protocol'),
      src_port: header.indexOf('src_port') !== -1 ? header.indexOf('src_port') : header.indexOf('src port'),
      dst_port: header.indexOf('dst_port') !== -1 ? header.indexOf('dst_port') : header.indexOf('dst port'),
      service: header.indexOf('service'),
      packet_size: header.indexOf('packet_size') !== -1 ? header.indexOf('packet_size') : header.indexOf('size (b)'),
    };

    const imported = [];
    for (let i = 1; i < lines.length; i++) {
      const cols = parseCSVLine(lines[i]);
      if (!cols.length) continue;
      imported.push({
        time: colMap.time >= 0 ? cols[colMap.time] || '' : '',
        src_ip: colMap.src_ip >= 0 ? cols[colMap.src_ip] || '' : '',
        dst_ip: colMap.dst_ip >= 0 ? cols[colMap.dst_ip] || '' : '',
        protocol: colMap.protocol >= 0 ? cols[colMap.protocol] || 'OTHER' : 'OTHER',
        src_port: colMap.src_port >= 0 ? cols[colMap.src_port] || '' : '',
        dst_port: colMap.dst_port >= 0 ? cols[colMap.dst_port] || '' : '',
        service: colMap.service >= 0 ? cols[colMap.service] || 'Unknown' : 'Unknown',
        packet_size: colMap.packet_size >= 0 ? parseInt(cols[colMap.packet_size]) || 0 : 0,
      });
    }

    allPackets = imported;
    currentPage = 1;

    // Recompute stats from imported data
    const stats = computeStats(allPackets);
    updateStats(stats);
    applyFilter();
    log(`Imported ${imported.length} packets from "${file.name}".`, 'success');
  };
  reader.readAsText(file);
  // Reset so same file can be re-imported
  event.target.value = '';
}

function parseCSVLine(line) {
  const result = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; }
    else if (ch === ',' && !inQuotes) { result.push(cur.trim()); cur = ''; }
    else { cur += ch; }
  }
  result.push(cur.trim());
  return result;
}

function computeStats(packets) {
  let tcp = 0, udp = 0, icmp = 0, other = 0, totalSize = 0;
  for (const p of packets) {
    const proto = (p.protocol || '').toUpperCase();
    if (proto === 'TCP') tcp++;
    else if (proto === 'UDP') udp++;
    else if (proto === 'ICMP') icmp++;
    else other++;
    totalSize += parseInt(p.packet_size) || 0;
  }
  return {
    total_packets: packets.length,
    tcp, udp, icmp, other,
    avg_size: packets.length ? Math.round(totalSize / packets.length) : 0,
    capturing: isCapturing
  };
}

// ── CSV EXPORT ────────────────────────────────────────────────
function exportCSV() {
  if (!allPackets.length) {
    log('No packets to export.', 'warn');
    return;
  }

  const headers = ['time', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'service', 'packet_size'];
  const rows = [headers.join(',')];

  for (const p of allPackets) {
    rows.push([
      csvCell(p.time),
      csvCell(p.src_ip),
      csvCell(p.dst_ip),
      csvCell(p.protocol),
      csvCell(p.src_port),
      csvCell(p.dst_port),
      csvCell(p.service),
      csvCell(p.packet_size)
    ].join(','));
  }

  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  a.href = url;
  a.download = `netwatch_capture_${ts}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  log(`Exported ${allPackets.length} packets to CSV.`, 'success');
}

function csvCell(val) {
  const s = String(val === null || val === undefined ? '' : val);
  return s.includes(',') || s.includes('"') || s.includes('\n')
    ? `"${s.replace(/"/g, '""')}"` : s;
}

// ── ESCAPE HTML ───────────────────────────────────────────────
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

  // Live IP validation
  document.getElementById('fSrcIP').addEventListener('input', function () { validateIPField(this); });
  document.getElementById('fDstIP').addEventListener('input', function () { validateIPField(this); });
  document.getElementById('fService').addEventListener('input', function () { validateServiceField(this); });
});
