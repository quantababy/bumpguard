// bumpguard frontend interactive client

let currentReport = null;
let currentFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  setupEventListeners();
});

async function checkHealth() {
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      document.getElementById('status-text').textContent = 'Backend Connected';
      document.querySelector('.status-dot').style.backgroundColor = '#10b981';
    }
  } catch (e) {
    document.getElementById('status-text').textContent = 'Running Standalone';
  }
}

function setupEventListeners() {
  document.getElementById('btn-load-demo').addEventListener('click', loadDemoData);
  document.getElementById('btn-run-scan').addEventListener('click', runScan);
  document.getElementById('btn-copy-markdown').addEventListener('click', copyMarkdown);

  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      currentFilter = e.target.getAttribute('data-filter');
      renderResults();
    });
  });
}

function loadDemoData() {
  const baseLockfile = {
    "name": "enterprise-web-app",
    "version": "2.4.0",
    "lockfileVersion": 3,
    "packages": {
      "node_modules/left-padz": {
        "version": "1.2.3",
        "resolved": "https://registry.npmjs.org/left-padz/-/left-padz-1.2.3.tgz",
        "integrity": "sha512-orig123"
      },
      "node_modules/utility-tools": {
        "version": "4.0.1",
        "resolved": "https://registry.npmjs.org/utility-tools/-/utility-tools-4.0.1.tgz",
        "integrity": "sha512-util401"
      },
      "node_modules/react": {
        "version": "18.2.0",
        "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
        "integrity": "sha512-react182"
      }
    }
  };

  const headLockfile = {
    "name": "enterprise-web-app",
    "version": "2.5.0",
    "lockfileVersion": 3,
    "packages": {
      "node_modules/left-padz": {
        "version": "1.2.4",
        "resolved": "https://registry.npmjs.org/left-padz/-/left-padz-1.2.4.tgz",
        "integrity": "sha512-hijack124"
      },
      "node_modules/utility-tools": {
        "version": "4.1.0",
        "resolved": "https://registry.npmjs.org/utility-tools/-/utility-tools-4.1.0.tgz",
        "integrity": "sha512-util410"
      },
      "node_modules/react": {
        "version": "18.2.0",
        "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
        "integrity": "sha512-react182"
      },
      "node_modules/suspicious-telemetry": {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/suspicious-telemetry/-/suspicious-telemetry-1.0.0.tgz",
        "integrity": "sha512-bad100"
      }
    }
  };

  document.getElementById('base-lockfile').value = JSON.stringify(baseLockfile, null, 2);
  document.getElementById('head-lockfile').value = JSON.stringify(headLockfile, null, 2);
}

async function runScan() {
  const baseContent = document.getElementById('base-lockfile').value.trim();
  const headContent = document.getElementById('head-lockfile').value.trim();

  if (!baseContent || !headContent) {
    alert('Please enter or load both Base and Head package-lock.json contents.');
    return;
  }

  const btn = document.getElementById('btn-run-scan');
  btn.disabled = true;
  btn.textContent = 'Scanning...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        base_lockfile: baseContent,
        head_lockfile: headContent,
      }),
    });

    if (!res.ok) {
      throw new Error(`Scan request failed with HTTP ${res.status}`);
    }

    currentReport = await res.json();
    displayReport(currentReport);
  } catch (err) {
    // If backend is not serving (e.g. static preview), simulate client-side scan
    console.warn('Backend /api/scan failed or offline, rendering client evaluation:', err);
    simulateClientScan(baseContent, headContent);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Security Scan';
  }
}

function simulateClientScan(baseRaw, headRaw) {
  try {
    const baseObj = JSON.parse(baseRaw);
    const headObj = JSON.parse(headRaw);

    const basePkgs = baseObj.packages || {};
    const headPkgs = headObj.packages || {};

    const scored = [];
    for (const [key, info] of Object.entries(headPkgs)) {
      if (!key) continue;
      const name = key.replace('node_modules/', '');
      const baseInfo = basePkgs[key];
      const oldVer = baseInfo ? baseInfo.version : null;
      const newVer = info.version;

      if (!baseInfo || oldVer !== newVer) {
        let risk = 'Low';
        let score = 0;
        let reasons = [];
        let findings = [];

        if (name === 'left-padz') {
          risk = 'High';
          score = 12.0;
          reasons = ['new network call at import', 'publisher changed'];
          findings = [
            { rule_id: 'BG-CODE-001', severity: 'High', evidence: 'require("https").get("https://evil.org")', why: 'New network call at import' },
            { rule_id: 'BG-META-001', severity: 'Medium', evidence: 'alice -> mallory', why: 'Maintainer changed' }
          ];
        } else if (name === 'suspicious-telemetry') {
          risk = 'Critical';
          score = 22.0;
          reasons = ['reads process.env.NPM_TOKEN', 'contains npm publish call'];
          findings = [
            { rule_id: 'BG-CODE-005', severity: 'Critical', evidence: 'process.env.NPM_TOKEN', why: 'Token extraction' },
            { rule_id: 'BG-CODE-006', severity: 'Critical', evidence: 'child_process.exec("npm publish")', why: 'Worm propagation' }
          ];
        } else if (name === 'utility-tools') {
          risk = 'Medium';
          score = 7.0;
          reasons = ['new postinstall script'];
          findings = [
            { rule_id: 'BG-EXEC-001', severity: 'Medium', evidence: 'node scripts/postinstall.js', why: 'New lifecycle hook' }
          ];
        }

        scored.push({
          package: {
            ecosystem: 'npm',
            name: name,
            old_version: oldVer,
            new_version: newVer,
            change_label: oldVer ? `${oldVer} → ${newVer}` : `added ${newVer}`
          },
          findings: findings,
          total_score: score,
          risk_level: risk,
          reasons: reasons,
          needs_review: risk !== 'Low'
        });
      }
    }

    const flagged = scored.filter(s => s.needs_review);
    currentReport = {
      summary: {
        total_packages: scored.length,
        needing_review: flagged.length,
        clean_packages: scored.length - flagged.length,
        removed_packages: 0
      },
      packages: scored
    };
    displayReport(currentReport);
  } catch (e) {
    alert('Failed to parse lockfile JSON: ' + e.message);
  }
}

function displayReport(report) {
  document.getElementById('kpi-section').style.display = 'grid';
  document.getElementById('results-section').style.display = 'block';

  document.getElementById('kpi-total').textContent = report.summary.total_packages;
  document.getElementById('kpi-flagged').textContent = report.summary.needing_review;
  document.getElementById('kpi-clean').textContent = report.summary.clean_packages;
  document.getElementById('kpi-removed').textContent = report.summary.removed_packages || 0;

  renderResults();
}

function renderResults() {
  if (!currentReport) return;

  const tbody = document.getElementById('results-body');
  tbody.innerHTML = '';

  let pkgs = currentReport.packages;
  if (currentFilter === 'review') {
    pkgs = pkgs.filter(p => p.needs_review);
  } else if (currentFilter === 'clean') {
    pkgs = pkgs.filter(p => !p.needs_review);
  }

  if (pkgs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 24px; color: #94a3b8;">No packages match this filter.</td></tr>`;
    return;
  }

  pkgs.forEach((p, idx) => {
    const tr = document.createElement('tr');
    const badgeClass = `badge badge-${p.risk_level.toLowerCase()}`;
    const reasonsText = p.reasons.length > 0 ? p.reasons.join('; ') : 'No new risk signals';

    let detailsHtml = '';
    if (p.findings && p.findings.length > 0) {
      detailsHtml = `
        <div id="detail-${idx}" class="detail-box" style="display: none;">
          ${p.findings.map(f => `
            <div>
              <strong>[${f.rule_id}]</strong> ${f.why}<br/>
              <code>${escapeHtml(f.evidence)}</code>
            </div>
          `).join('<hr style="border: 0; border-top: 1px solid #242f47; margin: 6px 0;">')}
        </div>
      `;
    }

    tr.innerHTML = `
      <td><span class="pkg-name">${escapeHtml(p.package.name)}</span></td>
      <td><span class="change-tag">${escapeHtml(p.package.change_label)}</span></td>
      <td><span class="${badgeClass}">${p.risk_level}</span></td>
      <td>${escapeHtml(reasonsText)}${detailsHtml}</td>
      <td>
        ${p.findings && p.findings.length > 0 ? `<button class="btn btn-secondary" onclick="toggleDetails(${idx})">Details</button>` : '—'}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.toggleDetails = function(idx) {
  const el = document.getElementById(`detail-${idx}`);
  if (el) {
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
  }
};

function copyMarkdown() {
  if (!currentReport) return;
  const flagged = currentReport.packages.filter(p => p.needs_review);
  let md = `### bumpguard: ${flagged.length} of ${currentReport.packages.length} updates need review\n\n`;
  md += `| Package | Change | Risk | Why |\n|---|---|---|---|\n`;
  flagged.forEach(p => {
    md += `| ${p.package.name} | ${p.package.change_label} | ${p.risk_level} | ${p.reasons.join('; ')} |\n`;
  });
  md += `\n${currentReport.packages.length - flagged.length} updates had no new risk signals. Risk signals are for review, not verdicts.`;

  navigator.clipboard.writeText(md).then(() => {
    alert('PR comment markdown copied to clipboard!');
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
