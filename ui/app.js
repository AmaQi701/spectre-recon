let currentProjectId = null;

function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  if (btn) btn.classList.add('active');
}

async function loadProjects() {
  const r = await fetch('/api/projects');
  const d = await r.json();
  const sel = document.getElementById('projectSelect');
  sel.innerHTML = '';
  (d.projects || []).forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = `#${p.id} ${p.name} (${p.primary_target})`;
    sel.appendChild(opt);
  });
  if (d.projects && d.projects.length > 0 && !currentProjectId) {
    currentProjectId = d.projects[0].id;
    sel.value = currentProjectId;
  }
  if (currentProjectId) loadProjectBundle();
}

async function createProject() {
  const payload = {
    name: document.getElementById('pName').value || 'Security Audit',
    primary_target: document.getElementById('pTarget').value,
    in_scope: document.getElementById('pInScope').value || document.getElementById('pTarget').value,
    out_of_scope: document.getElementById('pOutScope').value,
    source_code_path: document.getElementById('pCodePath').value,
  };
  const r = await fetch('/api/projects', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  const d = await r.json();
  if (d.project_id) {
    currentProjectId = d.project_id;
    await loadProjects();
    document.getElementById('projectSelect').value = currentProjectId;
    loadProjectBundle();
  } else {
    alert(d.error || 'Xatolik');
  }
}

async function loadProjectBundle() {
  const sel = document.getElementById('projectSelect');
  if (sel.value) currentProjectId = parseInt(sel.value, 10);
  if (!currentProjectId) return;

  const r = await fetch(`/api/projects/${currentProjectId}/bundle`);
  const b = await r.json();
  const p = b.project || {};
  document.getElementById('activeProjTitle').textContent = `${p.name || ''} — [${p.primary_target || ''}]`;
  document.getElementById('activeProjStatus').textContent = p.status || 'READY';

  document.getElementById('stDomains').textContent = (b.domains || []).length;
  document.getElementById('stHttp').textContent = `${(b.ports || []).length} port / ${(b.http_services || []).length} web`;
  document.getElementById('stEndpoints').textContent = (b.endpoints || []).length;
  document.getElementById('stFindings').textContent = `${(b.findings || []).length} / ${(b.bug_chains || []).length} chain`;

  document.getElementById('tbHttp').innerHTML = (b.http_services || []).map(s => {
    const tech = JSON.parse(s.tech_stack || '[]').join(', ');
    const sec = JSON.parse(s.security_headers_json || '{}');
    const missing = Object.entries(sec).filter(([_, v]) => !v).map(([k]) => k).join(', ');
    return `<tr>
      <td><a href="${s.url}" target="_blank" style="color:#38bdf8">${s.url}</a><br><small>Score: ${s.priority_score}</small></td>
      <td><span class="badge b-Low">${s.status_code}</span></td>
      <td><b>${s.title || '-'}</b><br><small>${s.server || ''}</small></td>
      <td>${tech || '-'} ${s.waf ? `<span class="badge b-Med">WAF: ${s.waf}</span>` : ''}</td>
      <td><small>Missing: ${missing || 'None'}</small></td>
    </tr>`;
  }).join('');

  const portsByHost = {};
  (b.ports || []).forEach(pt => {
    portsByHost[pt.host] = portsByHost[pt.host] || [];
    portsByHost[pt.host].push(`${pt.port}/${pt.protocol} (${pt.service} ${pt.version})`);
  });
  document.getElementById('tbDomains').innerHTML = (b.domains || []).map(d => `<tr>
    <td><b>${d.domain}</b></td>
    <td><code>${d.ip || '-'}</code> ${d.cname ? `<br><small>CNAME: ${d.cname}</small>` : ''}</td>
    <td><span class="badge b-Low">${d.source}</span> ${(portsByHost[d.domain] || []).map(x => `<code>${x}</code>`).join(' ')}</td>
  </tr>`).join('');

  document.getElementById('tbEndpoints').innerHTML = (b.endpoints || []).map(e => {
    const params = JSON.parse(e.params_json || '[]');
    const risks = JSON.parse(e.risk_tags_json || '[]');
    return `<tr>
      <td><span class="badge b-Low">${e.method}</span> <code>${e.url}</code></td>
      <td>${params.map(x => `<code>${x}</code>`).join(' ') || '-'}</td>
      <td><small>${e.category} (${e.source})</small> ${risks.map(r => `<span class="badge b-High">${r}</span>`).join(' ')}</td>
      <td><button class="btn" style="padding:4px 8px" onclick="copyCurl('${e.method}', '${e.url}')">📋 Copy cURL</button></td>
    </tr>`;
  }).join('');

  const tbJs = document.getElementById('tbJsAssets');
  if (tbJs) {
    tbJs.innerHTML = (b.js_assets || []).map(j => {
      const eps = JSON.parse(j.endpoints_json || '[]');
      const prm = JSON.parse(j.params_json || '[]');
      const snk = JSON.parse(j.sinks_json || '[]');
      const sec = JSON.parse(j.secrets_hints_json || '[]');
      return `<tr>
        <td><a href="${j.js_url}" target="_blank" style="color:#38bdf8">${j.js_url.split('/').pop()}</a></td>
        <td>${eps.slice(0, 12).map(x => `<code>${x}</code>`).join(' ') || '-'}</td>
        <td>${prm.slice(0, 15).map(x => `<code>${x}</code>`).join(' ') || '-'}</td>
        <td>
          ${snk.map(x => `<span class="badge b-Med">Sink: ${x}</span>`).join(' ')}
          ${sec.map(x => `<span class="badge b-High">${x}</span>`).join(' ')}
        </td>
      </tr>`;
    }).join('');
  }

  document.getElementById('tbFindings').innerHTML = (b.findings || []).map(f => {
    const cls = (f.severity === 'Critical' || f.severity === 'High') ? 'b-High' : (f.severity === 'Medium' ? 'b-Med' : 'b-Low');
    return `<tr>
      <td><span class="badge ${cls}">${f.severity} (${f.cvss_score})</span><br><small>${f.confidence}</small></td>
      <td><b>${f.title}</b><br><small>${f.cwe} | ${f.owasp}</small></td>
      <td><code>${f.asset}</code><br><small>${f.evidence}</small></td>
      <td><small>${f.remediation}</small></td>
      <td>
        <select onchange="setTriage(${f.id}, this.value)" style="margin:0;width:125px">
          <option ${f.triage_status==='Verified'?'selected':''}>Verified</option>
          <option ${f.triage_status==='Manual-Review'?'selected':''}>Manual-Review</option>
          <option ${f.triage_status==='False-Positive'?'selected':''}>False-Positive</option>
        </select>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('tbChains').innerHTML = (b.bug_chains || []).map(c => {
    const nodes = JSON.parse(c.nodes_json || '[]').join(' ➔ ');
    return `<tr>
      <td><span class="badge b-High">${c.severity} (${c.cvss_score})</span><br><b>${c.chain_title}</b></td>
      <td><code>${nodes}</code></td>
      <td>${c.attack_scenario}<br><small style="color:#f87171">Impact: ${c.impact}</small></td>
      <td><small>${c.remediation}</small></td>
    </tr>`;
  }).join('');

  const term = document.getElementById('liveTerminal');
  if (b.live_logs && b.live_logs.length) {
    term.textContent = b.live_logs.join('\n');
    term.scrollTop = term.scrollHeight;
  }
}

function copyCurl(method, url) {
  const auth = document.getElementById('greyboxAuth').value.trim();
  const hFlag = auth ? ` -H "${auth.includes(':') ? auth : 'Cookie: ' + auth}"` : '';
  const cmd = `curl -i -s -k -X ${method}${hFlag} "${url}"`;
  navigator.clipboard.writeText(cmd);
  alert('cURL komandasi nusxalandi:\n' + cmd);
}

async function setTriage(findingId, status) {
  await fetch(`/api/findings/${findingId}/triage`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({triage_status: status}) });
  loadProjectBundle();
}

async function runAgent(agent) {
  if (!currentProjectId) return alert('Avval loyiha yarating yoki tanlang!');
  const auth = document.getElementById('greyboxAuth').value;
  await fetch(`/api/projects/${currentProjectId}/run_agent`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ agent, auth_header: auth })
  });
}

async function abortRun() {
  if (!currentProjectId) return;
  await fetch(`/api/projects/${currentProjectId}/abort`, { method: 'POST' });
  loadProjectBundle();
}

async function addManualFinding() {
  if (!currentProjectId) return;
  const payload = {
    title: document.getElementById('mTitle').value,
    severity: document.getElementById('mSev').value,
    cvss_score: document.getElementById('mCvss').value,
    asset: document.getElementById('mAsset').value,
    evidence: document.getElementById('mEvid').value,
    remediation: document.getElementById('mRem').value,
  };
  await fetch(`/api/projects/${currentProjectId}/manual_finding`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  loadProjectBundle();
}

async function generateReport() {
  if (!currentProjectId) return;
  const r = await fetch(`/api/projects/${currentProjectId}/report`, { method: 'POST' });
  const d = await r.json();
  document.getElementById('reportPreview').textContent = `Saqlandi:\n- ${d.markdown_path}\n- ${d.html_path}\n\n` + (d.markdown_preview || '');
}

async function loadTools() {
  const r = await fetch('/api/tools');
  const d = await r.json();
  document.getElementById('tbTools').innerHTML = (d.tools || []).map(t => `<tr>
    <td><input type="checkbox" ${t.enabled ? 'checked' : ''} onchange="toggleTool('${t.id}', this.checked)" style="width:auto"/></td>
    <td><b>${t.name}</b><br><small>${t.description}</small></td>
    <td><code>${t.stage}</code></td>
    <td><span class="badge ${t.installed ? 'b-Low' : 'b-High'}">${t.installed ? 'READY' : 'MISSING'}</span><br><small>${t.resolved_path}</small></td>
    <td><code>${t.command_template}</code></td>
  </tr>`).join('');
}

async function toggleTool(id, enabled) {
  await fetch('/api/tools', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({action:'toggle', id, enabled}) });
}

async function auditJwt() {
  const token = document.getElementById('jwtInput').value;
  const r = await fetch('/api/jwt/audit', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({token}) });
  const d = await r.json();
  document.getElementById('jwtOutput').textContent = JSON.stringify(d, null, 2);
}

loadProjects();
loadTools();
setInterval(() => { if (currentProjectId) loadProjectBundle(); }, 2500);


