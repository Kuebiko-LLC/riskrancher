const fileInput = document.getElementById('local-file');
const pathInput = document.getElementById('findings_path');
let currentRawData = null;
let isJson = false;

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    isJson = file.name.toLowerCase().endsWith('.json');

    const reader = new FileReader();
    reader.onload = (event) => {
        currentRawData = event.target.result;
        document.getElementById('preview-placeholder').style.display = 'none';

        if (isJson) {
            try {
                const parsed = JSON.parse(currentRawData);
                const guessedPath = autoDetectArrayPath(parsed);
                if (guessedPath) {
                    pathInput.value = guessedPath;
                }
            } catch (e) {
                console.error("Auto-detect failed:", e);
            }
        }

        processPreview();
    };
    reader.readAsText(file);
});

pathInput.addEventListener('input', () => {
    if (currentRawData && isJson) processPreview();
});

function autoDetectArrayPath(obj) {
    if (Array.isArray(obj)) return ".";

    let bestPath = "";
    let maxLen = -1;

    function search(currentObj, currentPath) {
        if (Array.isArray(currentObj)) {
            if (currentObj.length > 0 && typeof currentObj[0] === 'object') {
                if (currentObj.length > maxLen) {
                    maxLen = currentObj.length;
                    bestPath = currentPath;
                }
            }
            return;
        }
        if (currentObj !== null && typeof currentObj === 'object') {
            for (let key in currentObj) {
                let nextPath = currentPath ? currentPath + "." + key : key;
                search(currentObj[key], nextPath);
            }
        }
    }

    search(obj, "");
    return bestPath || ".";
}

function processPreview() {
    let headers = [];
    let rows = [];

    if (isJson) {
        try {
            const parsed = JSON.parse(currentRawData);
            const findings = getNestedValue(parsed, pathInput.value);

            if (!Array.isArray(findings) || findings.length === 0) {
                const rawPreview = JSON.stringify(parsed, null, 2).substring(0, 1500) + "\n\n... (file truncated for preview)";

                document.getElementById('preview-table-container').innerHTML =
                    `<div style="padding: 15px; background: #1e293b; border-radius: 6px; font-family: monospace; overflow-x: auto; text-align: left; font-size: 0.85rem;">
                        <p style="color: #fca5a5; margin-top: 0; font-weight: bold;">⚠️ Path "${pathInput.value}" is not an array.</p>
                        <p style="color: #cbd5e1; margin-bottom: 10px;">Here is the structure of your file to help you find the correct path:</p>
                        <pre style="margin: 0; color: #a6e22e;">${rawPreview}</pre>
                    </div>`;

                document.getElementById('save-btn').classList.add('disabled');
                return;
            }

            document.getElementById('save-btn').classList.remove('disabled');
            headers = Object.keys(findings[0]);
            rows = findings.slice(0, 5).map(obj => headers.map(h => formatCell(obj[h])));
        } catch(e) {
            document.getElementById('preview-table-container').innerHTML = `<div style="color: var(--critical); padding: 20px; font-weight: bold;">JSON Parse Error: ${e.message}</div>`;
            return;
        }
    } else {
        const lines = currentRawData.split('\n').filter(l => l.trim() !== '');
        headers = lines[0].split(',').map(h => h.trim());
        rows = lines.slice(1, 6).map(line => line.split(',').map(c => c.trim()));
        document.getElementById('save-btn').classList.remove('disabled');
    }

    renderTable(headers, rows);
    populateDropdowns(headers);
}

function getNestedValue(obj, path) {
    if (path === '' || path === '.') return obj;
    return path.split('.').reduce((acc, part) => acc && acc[part], obj);
}

function formatCell(val) {
    if (typeof val === 'object') return JSON.stringify(val);
    if (val === undefined || val === null) return "";
    const str = String(val);
    return str.length > 50 ? str.substring(0, 47) + "..." : str;
}

function renderTable(headers, rows) {
    let html = '<table style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">';
    html += '<thead style="background: #f8fafc; text-transform: uppercase; color: #64748b;"><tr>' + headers.map(h => `<th style="padding: 10px; border-bottom: 2px solid #e2e8f0; text-align: left;">${h}</th>`).join('') + '</tr></thead><tbody>';
    rows.forEach(row => {
        html += '<tr>' + row.map(cell => `<td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">${cell}</td>`).join('') + '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('preview-table-container').innerHTML = html;
}

function populateDropdowns(headers) {
    const selects = document.querySelectorAll('.source-header');
    selects.forEach(select => {
        select.innerHTML = '<option value="">-- Select Column --</option>';
        headers.forEach(h => {
            const opt = document.createElement('option');
            opt.value = h;
            opt.textContent = h;
            select.appendChild(opt);
        });
    });
}

// Reusable save function mapped to the API
async function saveAdapterToAPI() {
    const data = {
        name: document.getElementById('name').value,
        source_name: document.getElementById('source_name').value,
        findings_path: document.getElementById('findings_path').value,
        mapping_title: document.getElementById('mapping_title').value,
        mapping_asset: document.getElementById('mapping_asset').value,
        mapping_severity: document.getElementById('mapping_severity').value,
        mapping_description: document.getElementById('mapping_description').value,
        mapping_remediation: document.getElementById('mapping_remediation').value
    };

    const resp = await fetch('/api/adapters', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });

    if (resp.ok) {
        alert("Adapter Saved! Taking you back to the Landing Zone.");
        window.location.href = "/ingest";
    } else {
        alert("Failed to save adapter: " + await resp.text());
    }
}

// Bound to the primary "Save & Enable Adapter" submit button
document.getElementById('adapter-form').onsubmit = async (e) => {
    e.preventDefault();
    await saveAdapterToAPI();
};

// Bound to the secondary "Save to Database" button
window.saveAdapter = async function() {
    const form = document.getElementById('adapter-form');
    // Ensure HTML validations (like 'required') are checked before saving
    if (form.reportValidity()) {
        await saveAdapterToAPI();
    }
};

window.exportAdapterJSON = function() {
    // Fixed mismatched Element IDs
    const name = document.getElementById("name").value.trim();
    const sourceName = document.getElementById("source_name").value.trim();
    const rootPath = document.getElementById("findings_path").value.trim();

    if (!name || !sourceName) {
        return alert("Adapter Name and Source Name are required to export.");
    }

    const payload = {
        name: name,
        source_name: sourceName,
        findings_path: rootPath,
        mapping_title: document.getElementById("mapping_title").value.trim(),
        mapping_asset: document.getElementById("mapping_asset").value.trim(),
        mapping_severity: document.getElementById("mapping_severity").value.trim(),
        mapping_description: document.getElementById("mapping_description").value.trim(),
        mapping_remediation: document.getElementById("mapping_remediation").value.trim()
    };

    // Create a downloadable JSON blob
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(payload, null, 4));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `${sourceName.toLowerCase().replace(/\s+/g, '_')}_adapter.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
};