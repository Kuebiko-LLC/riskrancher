window.showUpsell = function(featureName) {
    const featureNameEl = document.getElementById('upsellFeatureName');
    const modalEl = document.getElementById('upsellModal');
    if (featureNameEl && modalEl) {
        featureNameEl.innerText = featureName;
        modalEl.style.display = 'flex';
    } else {
        alert("This feature (" + featureName + ") is available in RiskRancher Pro!");
    }
};

window.renderMarkdown = function(text) {
    if (!text) return "<i style='color:#94a3b8;'>No description provided.</i>";
    let html = text.replace(/!\[.*?\]\((.*?)\)/g, '<br><img src="$1" style="max-width: 100%; max-height: 400px; object-fit: contain; border: 1px solid #e2e8f0; border-radius: 4px; margin: 10px 0; display: block; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);"><br>');
    html = html.replace(/\n/g, '<br>');
    return html;
};

window.updateDrawerPreview = function() {
    const rawDesc = document.getElementById('drawerDescEdit').value;
    document.getElementById('drawerDescPreview').innerHTML = renderMarkdown(rawDesc);
};

window.openDrawer = function(id, title, asset, severity) {
    document.getElementById('drawerTicketID').value = id;
    document.getElementById('drawerTitle').innerText = title;
    document.getElementById('drawerAsset').innerText = asset;

    const badge = document.getElementById('drawerBadge');
    badge.innerText = severity;
    badge.className = `badge ${severity.toLowerCase()}`;

    // Read hidden inputs from the table row
    const rawDesc = document.getElementById('desc-' + id) ? document.getElementById('desc-' + id).value : "";
    const rawRem = document.getElementById('rem-' + id) ? document.getElementById('rem-' + id).value : "";
    const rawEv = document.getElementById('ev-' + id) ? document.getElementById('ev-' + id).value : "";
    const status = document.getElementById('status-' + id) ? document.getElementById('status-' + id).value : "";
    const rawComment = document.getElementById('comment-' + id) ? document.getElementById('comment-' + id).value : "";
    const assignee = document.getElementById('assignee-' + id) ? document.getElementById('assignee-' + id).value : "";

    // Set initial values in the drawer
    document.getElementById('drawerSeverity').value = severity;
    document.getElementById('drawerStatus').value = status; // Pre-select current status
    document.getElementById('drawerComment').value = "";
    document.getElementById('drawerDescEdit').value = rawDesc;
    document.getElementById('drawerRemEdit').value = rawRem;

    const drawerAssignee = document.getElementById('drawerAssignee');
    if (drawerAssignee) {
        drawerAssignee.value = (assignee === "Unassigned") ? "" : assignee;
    }

    const evBlock = document.getElementById('drawerEvidenceBlock');
    const evText = document.getElementById('drawerEvidenceText');
    if (evBlock && evText) {
        if (rawEv && rawEv.trim() !== "") {
            evText.innerText = rawEv;
            evBlock.style.display = "block";
        } else {
            evBlock.style.display = "none";
            evText.innerText = "";
        }
    }

    const retBlock = document.getElementById('drawerReturnedBlock');
    const retText = document.getElementById('drawerReturnedText');
    if (retBlock && retText) {
        if (status === 'Returned to Security' && rawComment) {
            retText.innerText = rawComment;
            retBlock.style.display = "block";
        } else {
            retBlock.style.display = "none";
            retText.innerText = "";
        }
    }

    const standardActions = document.getElementById('drawerStandardActions');
    const editControls = document.getElementById('drawerEditControls');

    if (window.CurrentTab === 'archives') {
        if(standardActions) standardActions.style.display = 'none';
        if(editControls) editControls.style.display = 'none';
    } else {
        if(standardActions) standardActions.style.display = 'flex';
        if(editControls) editControls.style.display = 'block';
    }

    updateDrawerPreview();

    document.getElementById('ticketDrawer').style.width = '600px';
    document.getElementById('ticketDrawer').classList.add('open');
    document.getElementById('drawerOverlay').style.display = 'block';
};

window.closeDrawer = function() {
    document.getElementById('ticketDrawer').classList.remove('open');
    document.getElementById('drawerOverlay').style.display = 'none';
};

window.openNewTicketModal = function() {
    // Clear out old values just in case
    document.getElementById('newTicketTitle').value = '';
    document.getElementById('newTicketAsset').value = '';
    document.getElementById('newTicketDesc').value = '';
    document.getElementById('newTicketSeverity').value = 'High';

    document.getElementById('newTicketModal').style.display = 'flex';
};

window.submitNewTicket = async function() {
    const title = document.getElementById('newTicketTitle').value.trim();
    const asset = document.getElementById('newTicketAsset').value.trim();
    const severity = document.getElementById('newTicketSeverity').value;
    const desc = document.getElementById('newTicketDesc').value.trim();

    if (!title || !asset) {
        return alert("Title and Asset Identifier are required!");
    }

    const payload = {
        title: title,
        asset_identifier: asset,
        severity: severity,
        description: desc,
        source: "Manual",
        status: "Waiting to be Triaged"
    };

    try {
        const res = await fetch('/api/tickets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            window.location.reload();
        } else {
            alert("Failed to create ticket.");
        }
    } catch (err) {
        alert("Network error.");
    }
};

window.toggleAssetGroup = function(safeAsset) {
    document.querySelectorAll(`.group-${safeAsset}`).forEach(r => {
        r.style.display = r.style.display === "none" ? "table-row" : "none";
    });
};

function initializeAssetTree() {
    const tbody = document.getElementById("ticketTableBody");
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll("tr.ticket-row"));
    if (rows.length === 0) {
        document.getElementById("mainTableHeader").style.display = "table-header-group";
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: #94a3b8; font-size: 0.95rem;">No tickets found in this queue. The ranch is quiet! 🤠</td></tr>`;
        return;
    }

    const assets = {};
    rows.forEach(r => {
        const asset = r.getAttribute("data-asset") || "Unknown";
        if (!assets[asset]) assets[asset] = [];
        assets[asset].push(r);
    });

    tbody.innerHTML = "";

    for (const asset in assets) {
        const findings = assets[asset];
        const safeAsset = asset.replace(/[^a-zA-Z0-9-_]/g, '-');

        let overdueCount = 0;
        let counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };

        findings.forEach(r => {
            const sev = r.querySelector('.badge').innerText.trim();
            if (counts[sev] !== undefined) counts[sev]++;
            const triageTimerSpan = r.querySelector('.triage-timer');
            if (triageTimerSpan) {
                const dueStr = triageTimerSpan.getAttribute('data-due');
                if (dueStr) {
                    const due = new Date(dueStr);
                    if (Math.ceil((due - new Date()) / (1000 * 60 * 60 * 24)) < 0) overdueCount++;
                }
            } else if (r.querySelector('span[style*="color: #dc2626"]')) {
                overdueCount++;
            }
        });

        let badges = '';
        if (counts.Critical > 0) badges += `<span class="badge critical" style="margin-left:8px;">${counts.Critical} C</span>`;
        if (counts.High > 0) badges += `<span class="badge high" style="margin-left:4px;">${counts.High} H</span>`;
        if (counts.Medium > 0) badges += `<span class="badge medium" style="margin-left:4px;">${counts.Medium} M</span>`;
        if (counts.Low > 0) badges += `<span class="badge low" style="margin-left:4px;">${counts.Low} L</span>`;
        if (overdueCount > 0) badges += `<span class="badge" style="background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; margin-left:8px;">overdue:${overdueCount}</span>`;

        let shareButtonHtml = '';
        if (window.CurrentTab === 'chute') {
            shareButtonHtml = `<button class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.75rem; color: #94a3b8; border-color: #e2e8f0;" onclick="showUpsell('Passwordless Magic Links')">🔒 Share Asset Link</button>`;
        } else if (window.CurrentTab === 'holding_pen') {
            shareButtonHtml = `<span style="font-size: 0.75rem; color: #94a3b8; font-style: italic;">Assign out to share</span>`;
        }

        const headerTr = document.createElement("tr");
        headerTr.className = "asset-header-row";
        headerTr.innerHTML = `
            <td style="padding: 12px 20px; background: #ffffff; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0;"><input type="checkbox" class="asset-cb" data-asset="${safeAsset}"></td>
            <td colspan="4" class="badges-cell" style="padding: 12px; background: #ffffff; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; cursor: pointer;" onclick="toggleAssetGroup('${safeAsset}')">
                <span style="font-family: monospace; font-size: 1.05rem; color: #1e293b; font-weight: bold;">📂 ${asset}</span>
                <span style="color: #64748b; font-size: 0.85rem; font-weight: normal; margin-left: 5px;">(${findings.length})</span> ${badges}
            </td>
            <td colspan="2" style="padding: 12px 20px; text-align: right; background: #ffffff; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0;">${shareButtonHtml}</td>
        `;
        tbody.appendChild(headerTr);

        const assetDetailsTr = document.createElement("tr");
        assetDetailsTr.className = `group-${safeAsset}`;
        assetDetailsTr.style.display = "none";
        assetDetailsTr.innerHTML = `
            <td colspan="7" style="padding: 0 20px 20px 60px; position: relative; background: #fafafa;">
                <div style="position: absolute; left: 35px; top: 0; bottom: 30px; width: 3px; background: #0f172a; border-radius: 2px;"></div>
                <div class="scroll-container" style="max-height: 350px; overflow-y: auto; overflow-x: hidden; padding-top: 10px; padding-right: 10px;">
                    <table class="nested-table" style="width: 100%; border-collapse: separate; border-spacing: 0 8px;"><tbody></tbody></table>
                </div>
            </td>
        `;
        tbody.appendChild(assetDetailsTr);

        const innerTableBody = assetDetailsTr.querySelector('tbody');
        findings.forEach(r => {
            r.style.boxShadow = "0 1px 2px rgba(0,0,0,0.05)";
            const cells = r.querySelectorAll('td');
            if (cells.length >= 6) { cells[1].style.width = "120px"; cells[2].style.width = "100px"; cells[4].style.width = "160px"; cells[5].style.width = "160px"; }
            innerTableBody.appendChild(r);
        });

        headerTr.querySelector('.asset-cb').addEventListener('change', function() {
            const isChecked = this.checked;
            innerTableBody.querySelectorAll('.ticket-cb').forEach(cb => cb.checked = isChecked);
        });
    }
}

document.addEventListener("DOMContentLoaded", function() {
    window.markFalsePositive = async function() {
        const id = parseInt(document.getElementById("drawerTicketID").value);
        const comment = document.getElementById("drawerComment").value;
        if (!comment.trim()) return alert("An audit trail comment is strictly required.");

        const btn = document.querySelector('button[onclick="markFalsePositive()"]');
        if (btn) {
            btn.innerText = "Processing...";
            btn.disabled = true;
        }

        try {
            const res = await fetch(`/api/tickets/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    status: "False Positive",
                    comment: "[False Positive] " + comment,
                    actor: "Analyst"
                })
            });
            if (res.ok) {
                window.location.reload();
            } else {
                alert("Failed.");
                if (btn) {
                    btn.innerText = "🚫 Mark False Positive";
                    btn.disabled = false;
                }
            }
        } catch (err) {
            alert("Network error.");
            if (btn) btn.disabled = false;
        }
    };

    document.querySelectorAll('.triage-timer').forEach(el => {
        const dueStr = el.getAttribute('data-due');
        if (!dueStr) return;
        const diffDays = Math.ceil((new Date(dueStr) - new Date()) / (1000 * 60 * 60 * 24));
        const baseStyle = "display: inline-block; white-space: nowrap; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold;";
        if (diffDays < 0) el.innerHTML = `<span style="${baseStyle} color: #dc2626; background: #fee2e2; border: 1px solid #fca5a5;">Overdue by ${Math.abs(diffDays)}d</span>`;
        else if (diffDays === 0) el.innerHTML = `<span style="${baseStyle} color: #ea580c; background: #ffedd5; border: 1px solid #fdba74;">Due Today</span>`;
        else el.innerHTML = `<span style="${baseStyle} color: #166534; background: #dcfce7; border: 1px solid #bbf7d0;">${diffDays} days left</span>`;
    });

    initializeAssetTree();

    const drawerSubmitBtn = document.getElementById("drawerSubmitBtn");
    if(drawerSubmitBtn) {
        drawerSubmitBtn.addEventListener("click", async function() {
            const id = document.getElementById("drawerTicketID").value;
            const newSev = document.getElementById("drawerSeverity").value;
            const comment = document.getElementById("drawerComment").value;
            const newDesc = document.getElementById("drawerDescEdit").value;
            const newRem = document.getElementById("drawerRemEdit").value;

            const assigneeInput = document.getElementById("drawerAssignee");
            const newAssignee = assigneeInput ? assigneeInput.value.trim() : "";

            // Explicitly grab the selected status from the new dropdown
            let explicitStatus = document.getElementById("drawerStatus").value;
            let newStatus = explicitStatus;

            // Helpful UX: If they typed an email but left the status as "Waiting", auto-assign it
            if (newAssignee !== "" && newAssignee !== "Unassigned" && explicitStatus === "Waiting to be Triaged") {
                newStatus = "Assigned Out";
            }

            if (!comment.trim()) return alert("An audit trail comment is strictly required when modifying a finding.");

            this.innerText = "Saving..."; this.disabled = true;
            try {
                const res = await fetch(`/api/tickets/${id}`, {
                    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        severity: newSev,
                        comment: comment,
                        description: newDesc,
                        recommended_remediation: newRem,
                        actor: "Analyst",
                        status: newStatus,
                        assignee: newAssignee || "Unassigned"
                    })
                });

                if (res.ok) window.location.reload();
                else { alert("Update failed."); this.innerText = "Save & Dispatch"; this.disabled = false; }
            } catch (err) { alert("Network error."); this.disabled = false; }
        });
    }
});