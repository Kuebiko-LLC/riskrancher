// File: RiskRancher/ui/static/dashboard.js


// ADDED: Open Modal and Clear Form
window.openNewTicketModal = function() {
    document.getElementById('newTicketTitle').value = '';
    document.getElementById('newTicketAsset').value = '';
    document.getElementById('newTicketDesc').value = '';
    document.getElementById('newTicketSeverity').value = 'High';

    document.getElementById('newTicketModal').style.display = 'flex';
};

// ADDED: Submit the API Request
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

    const btn = document.querySelector('button[onclick="submitNewTicket()"]');
    if(btn) { btn.innerText = "Creating..."; btn.disabled = true; }

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
            if(btn) { btn.innerText = "Create Finding"; btn.disabled = false; }
        }
    } catch (err) {
        alert("Network error.");
        if(btn) { btn.innerText = "Create Finding"; btn.disabled = false; }
    }
};

// 1. The Markdown Renderer
window.renderMarkdown = function(text) {
    if (!text) return "<i style='color:#94a3b8;'>No description provided.</i>";
    // Escape first: the text is ingested (scanner/operator), so every character is inert
    // before we add our own trusted markup. The markdown syntax below survives escaping,
    // and the captured image URL is escaped so it cannot break out of the src attribute.
    let html = esc(text);
    // Render images with constraints so they don't break the drawer layout!
    html = html.replace(/!\[.*?\]\((.*?)\)/g, '<br><img src="$1" style="max-width: 100%; max-height: 400px; object-fit: contain; border: 1px solid #e2e8f0; border-radius: 4px; margin: 10px 0; display: block; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);"><br>');
    // Render line breaks
    html = html.replace(/\n/g, '<br>');
    return html;
};

// 2. Live Preview Updater
window.updateDrawerPreview = function() {
    const rawDesc = document.getElementById('drawerDescEdit').value;
    document.getElementById('drawerDescPreview').innerHTML = renderMarkdown(rawDesc);
};

// 3. Update openDrawer to grab the new fields
window.openDrawer = function(id, title, asset, severity) {
    document.getElementById('drawerTicketID').value = id;
    document.getElementById('drawerTitle').innerText = title;
    document.getElementById('drawerAsset').innerText = asset;
    // How the priority was reached: the scanner's word, the asset's multipliers, the score
    const ctx = document.getElementById('ctx-' + id);
    const contextLine = document.getElementById('drawerContext');
    if (contextLine) contextLine.innerText = ctx ? ctx.value : "";

    const badge = document.getElementById('drawerBadge');
    badge.innerText = severity;
    badge.className = `badge ${severity.toLowerCase()}`;

    document.getElementById('drawerSeverity').value = severity;
    document.getElementById('drawerComment').value = "";

    // Everything that happened to this finding, newest first
    const history = document.getElementById('drawerHistory');
    if (history) {
        history.innerText = "Loading...";
        fetch(`/api/tickets/${id}/activity`).then(r => r.ok ? r.json() : []).then(entries => {
            if (!entries.length) { history.innerText = "No changes recorded yet."; return; }
            history.innerHTML = entries.map(e => {
                const when = e.at ? new Date(e.at).toLocaleString() : "";
                const what = (e.type || "").replace(/_/g, " ");
                const detail = e.old_value && e.new_value ? `${e.old_value} \u2192 ${e.new_value}` : (e.new_value || "");
                const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
                return `<div style="padding: 4px 0; border-bottom: 1px dashed #e2e8f0;"><strong>${esc(e.actor)}</strong> ${esc(what)} <span style="color: #64748b;">${esc(detail)}</span><div style="color: #94a3b8; font-size: 0.72rem;">${esc(when)}</div></div>`;
            }).join("");
        }).catch(() => { history.innerText = "History unavailable."; });
    }

// Grab the raw markdown from the hidden textareas using .value!
    const rawDesc = document.getElementById('desc-' + id) ? document.getElementById('desc-' + id).value : "";
    const rawRem = document.getElementById('rem-' + id) ? document.getElementById('rem-' + id).value : "";
    // Grab the evidence!
    const rawEv = document.getElementById('ev-' + id) ? document.getElementById('ev-' + id).value : "";
// Grab Status and Comment
    const status = document.getElementById('status-' + id) ? document.getElementById('status-' + id).value : "";
    const rawComment = document.getElementById('comment-' + id) ? document.getElementById('comment-' + id).value : "";
    document.getElementById('drawerDescEdit').value = rawDesc;
    document.getElementById('drawerRemEdit').value = rawRem;

    // Toggle the Evidence Box if evidence exists
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

    // Toggle Return Reason Box
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

    // Contextual Rendering for the Drawer UI
    const standardActions = document.getElementById('drawerStandardActions');
    const verifyActions = document.getElementById('drawerVerifyActions');
    const editControls = document.getElementById('drawerEditControls');

    if (window.CurrentTab === 'verification') {
        // Pending Verification: Show Evidence & Verify Buttons, Hide Editing
        if(standardActions) standardActions.style.display = 'none';
        if(verifyActions) verifyActions.style.display = 'flex';
        if(editControls) editControls.style.display = 'none';
    } else if (window.CurrentTab === 'archives') {
        // The Graveyard: Show Nothing but the data (Pure Read-Only)
        if(standardActions) standardActions.style.display = 'none';
        if(verifyActions) verifyActions.style.display = 'none';
        if(editControls) editControls.style.display = 'none';
    } else {
        // Holding Pen / Normal Triage: Show Full Edit Controls
        if(standardActions) standardActions.style.display = 'flex';
        if(verifyActions) verifyActions.style.display = 'none';
        if(editControls) editControls.style.display = 'block';
    }

    updateDrawerPreview();

    // Make the drawer a bit wider if it isn't already to accommodate images
    document.getElementById('ticketDrawer').style.width = '600px';
    document.getElementById('ticketDrawer').classList.add('open');
    document.getElementById('drawerOverlay').style.display = 'block';
};

window.closeDrawer = function() {
    document.getElementById('ticketDrawer').classList.remove('open');
    document.getElementById('drawerOverlay').style.display = 'none';
};

window.verifyTicket = async function(id) {
    if(!confirm("Verify this finding is fully remediated and close the ticket?")) return;
    try {
        const res = await fetch('/api/tickets/bulk', {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ticket_ids: [parseInt(id)], status: "Patched", comment: "Analyst verified evidence.", actor: "Analyst" })
        });
        if (res.ok) window.location.reload();
        else alert("Failed to verify.");
    } catch(e) { alert("Network error"); }
};

window.rejectTicket = async function(id) {
    const reason = prompt("Enter the reason for rejection (Required):");
    if (!reason) return;
    try {
        const res = await fetch('/api/tickets/bulk', {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ticket_ids: [parseInt(id)], status: "Assigned Out", comment: "[Rework Required] " + reason, actor: "Analyst" })
        });
        if (res.ok) window.location.reload();
        else alert("Failed to reject.");
    } catch(e) { alert("Network error"); }
};

// Drawer action wrappers
window.verifyFromDrawer = function() {
    const id = document.getElementById("drawerTicketID").value;
    window.verifyTicket(id);
};

window.rejectFromDrawer = function() {
    const id = document.getElementById("drawerTicketID").value;
    window.rejectTicket(id);
};

window.toggleAssetGroup = function(safeAsset) {
    document.querySelectorAll(`.group-${safeAsset}`).forEach(r => {
        r.style.display = r.style.display === "none" ? "table-row" : "none";
    });
};

window.copyMagicLink = function(token, btnElement, event) {
    if (event) event.stopPropagation();
    const shareUrl = window.location.origin + "/share/" + token;
    navigator.clipboard.writeText(shareUrl).then(() => {
        const originalText = btnElement.innerText;
        btnElement.innerText = "Copied!";
        btnElement.style.background = "#059669";
        btnElement.style.color = "white";
        setTimeout(() => {
            btnElement.innerText = originalText;
            btnElement.style.background = "";
            btnElement.style.color = "";
        }, 2000);
    });
};

function initializeAssetTree() {
    const tbody = document.getElementById("ticketTableBody");
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll("tr.ticket-row"));
    if (rows.length === 0) {
        document.getElementById("mainTableHeader").style.display = "table-header-group";
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: #94a3b8; font-size: 0.95rem;">No tickets found in this queue. The ranch is quiet!</td></tr>`;
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

        const firstToken = findings[0].getAttribute("data-token");
        // What the inventory says about the asset, when it is in it
        const exposure = findings[0].getAttribute("data-exposure") || "";
        const criticality = findings[0].getAttribute("data-criticality") || "";
        const assetContext = (exposure && criticality)
            ? `<span style="font-size: 0.75rem; color: #64748b; margin-left: 8px;">${exposure}, ${criticality}</span>`
            : '';
        let shareButtonHtml = '';
        if (window.CurrentTab === 'chute') {
            shareButtonHtml = `<button class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.75rem; background: #8b5cf6; color: white; border: none;" onclick="copyMagicLink('${firstToken}', this, event)">Share Asset Link</button>`;
        } else if (window.CurrentTab === 'holding_pen') {
            shareButtonHtml = `<span style="font-size: 0.75rem; color: #94a3b8; font-style: italic;">Assign out to share</span>`;
        }

        const headerTr = document.createElement("tr");
        headerTr.className = "asset-header-row";
        headerTr.innerHTML = `
            <td style="padding: 12px 20px; background: #ffffff; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0;"><input type="checkbox" class="asset-cb" data-asset="${safeAsset}"></td>
            <td colspan="4" class="badges-cell" style="padding: 12px; background: #ffffff; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; cursor: pointer;" onclick="toggleAssetGroup('${safeAsset}')">
                <span style="font-family: monospace; font-size: 1.05rem; color: #1e293b; font-weight: bold;">${asset}</span>
                <span style="color: #64748b; font-size: 0.85rem; font-weight: normal; margin-left: 5px;">(${findings.length})</span>${assetContext} ${badges}
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
            if(typeof window.updateBulkButton === "function") window.updateBulkButton();
        });
    }
}

document.addEventListener("DOMContentLoaded", function() {
    window.markFalsePositive = async function() {
        const id = parseInt(document.getElementById("drawerTicketID").value);
        const comment = document.getElementById("drawerComment").value;
        if (!comment.trim()) return alert("An audit trail comment is strictly required.");
        const btn = document.querySelector('button[onclick="markFalsePositive()"]');
        btn.innerText = "Processing..."; btn.disabled = true;
        try {
            const res = await fetch('/api/tickets/bulk', {
                method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ticket_ids: [id], status: "False Positive", comment: "[False Positive] " + comment, actor: "Analyst" })
            });
            if (res.ok) window.location.reload(); else { alert("Failed."); btn.innerText = "Mark False Positive"; btn.disabled = false; }
        } catch (err) { alert("Network error."); btn.disabled = false; }
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

            // Grab the edited description & remediation
            const newDesc = document.getElementById("drawerDescEdit").value;
            const newRem = document.getElementById("drawerRemEdit").value;

            if (!comment.trim()) return alert("An audit trail comment is strictly required when modifying a finding.");

            this.innerText = "Saving..."; this.disabled = true;
            try {
                // Hit the inline update endpoint (/api/tickets/{id}) instead of the Bulk endpoint!
                const res = await fetch(`/api/tickets/${id}`, {
                    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ severity: newSev, comment: comment, description: newDesc, recommended_remediation: newRem, actor: "Analyst" })
                });

                if (res.ok) window.location.reload();
                else { alert("Update failed: " + await res.text()); this.innerText = "Save Changes"; this.disabled = false; }
            } catch (err) { alert("Network error."); this.disabled = false; }
        });
    }

    const bulkBtn = document.getElementById("bulkActionBtn");
    const modal = document.getElementById("bulkModal");

// Support both standard and contextual bulk buttons
    window.updateBulkButton = function() {
        const checkedCount = document.querySelectorAll('.ticket-cb:checked').length;

        // Standard Bulk Button
        const bulkBtn = document.getElementById("bulkActionBtn");
        if (bulkBtn) {
            bulkBtn.textContent = `Bulk Actions (${checkedCount} selected)`;
            if (checkedCount > 0) { bulkBtn.classList.remove("disabled"); bulkBtn.style.backgroundColor = "#2563eb"; bulkBtn.style.color = "white"; }
            else { bulkBtn.classList.add("disabled"); bulkBtn.style.backgroundColor = ""; bulkBtn.style.color = ""; }
        }

        // Verification Bulk Buttons
        const verifyBtn = document.getElementById("bulkVerifyBtn");
        const rejectBtn = document.getElementById("bulkRejectBtn");
        if (verifyBtn && rejectBtn) {
            verifyBtn.textContent = `Verify (${checkedCount})`;
            rejectBtn.textContent = `Reject (${checkedCount})`;
            if (checkedCount > 0) {
                verifyBtn.classList.remove("disabled"); rejectBtn.classList.remove("disabled");
            } else {
                verifyBtn.classList.add("disabled"); rejectBtn.classList.add("disabled");
            }
        }
    };

    const tbody = document.getElementById("ticketTableBody");
    if(tbody) tbody.addEventListener("change", function(e) { if (e.target && e.target.classList.contains("ticket-cb")) window.updateBulkButton(); });

    if(bulkBtn) {
        bulkBtn.addEventListener("click", function() {
            if (this.classList.contains("disabled")) return;
            document.getElementById("bulkCountDisplay").textContent = document.querySelectorAll('.ticket-cb:checked').length;
            document.getElementById("bulkFormContainer").style.display = "block";
            document.getElementById("bulkSuccessContainer").style.display = "none";
            document.getElementById("submitBulk").innerText = "Confirm Update";
            document.getElementById("submitBulk").disabled = false;
            modal.style.display = "flex";
        });
    }

    const cancelBulk = document.getElementById("cancelBulk");
    if(cancelBulk) cancelBulk.addEventListener("click", () => modal.style.display = "none");

    const bulkStatus = document.getElementById("bulkStatus");
    if(bulkStatus) {
        bulkStatus.addEventListener("change", function() {
            document.getElementById("assigneeContainer").style.display = this.value === "Assigned Out" ? "block" : "none";
        });
    }

    const submitBulk = document.getElementById("submitBulk");
    if(submitBulk) {
        submitBulk.addEventListener("click", async function() {
            const status = document.getElementById("bulkStatus").value;
            let comment = document.getElementById("bulkComment").value;
            const assignee = document.getElementById("bulkAssignee").value;

            if (status === "Assigned Out" && assignee.trim() === "") return alert("Please provide an Assignee Email!");
            if (status === "False Positive") comment = "[False Positive] " + comment;

            const selectedCheckboxes = document.querySelectorAll('.ticket-cb:checked');
            const selectedIds = Array.from(selectedCheckboxes).map(cb => parseInt(cb.value));
            const firstToken = selectedCheckboxes.length > 0 ? selectedCheckboxes[0].closest('tr').getAttribute('data-token') : null;

            this.innerText = "Processing..."; this.disabled = true;

            try {
                const res = await fetch('/api/tickets/bulk', {
                    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ticket_ids: selectedIds, status: status, comment: comment, assignee: assignee, actor: "Analyst" })
                });

                if (res.ok) {
                    if (status === "Assigned Out" && firstToken) {
                        document.getElementById("bulkFormContainer").style.display = "none";
                        document.getElementById("bulkSuccessContainer").style.display = "block";
                        document.getElementById("bulkSuccessLinkArea").innerHTML = `<button class="btn" style="background: #10b981; color: white; padding: 12px 24px; font-size: 1.1rem; border: none; border-radius: 6px; cursor: pointer;" onclick="copyMagicLink('${firstToken}', this, event)">Copy IT Magic Link</button>`;
                    } else {
                        window.location.reload();
                    }
                } else {
                    alert("Update failed: " + await res.text());
                    this.innerText = "Confirm Update"; this.disabled = false;
                }
            } catch (err) { alert("Network error."); this.disabled = false; }
        });
    }
    // Execute Bulk Verify/Reject without the modal
    const bulkVerifyBtn = document.getElementById("bulkVerifyBtn");
    if (bulkVerifyBtn) {
        bulkVerifyBtn.addEventListener("click", async function() {
            if (this.classList.contains("disabled")) return;
            if (!confirm("Verify all selected findings and close the tickets?")) return;

            const selectedIds = Array.from(document.querySelectorAll('.ticket-cb:checked')).map(cb => parseInt(cb.value));
            this.innerText = "Verifying..."; this.disabled = true;

            try {
                const res = await fetch('/api/tickets/bulk', {
                    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ticket_ids: selectedIds, status: "Patched", comment: "Analyst bulk verified evidence.", actor: "Analyst" })
                });
                if (res.ok) window.location.reload();
                else { alert("Failed."); this.innerText = `Verify (${selectedIds.length})`; this.disabled = false; }
            } catch(e) { alert("Network error"); this.disabled = false; }
        });
    }

    const bulkRejectBtn = document.getElementById("bulkRejectBtn");
    if (bulkRejectBtn) {
        bulkRejectBtn.addEventListener("click", async function() {
            if (this.classList.contains("disabled")) return;
            const reason = prompt("Enter the reason for rejecting these fixes (Required):");
            if (!reason) return;

            const selectedIds = Array.from(document.querySelectorAll('.ticket-cb:checked')).map(cb => parseInt(cb.value));
            this.innerText = "Rejecting..."; this.disabled = true;

            try {
                const res = await fetch('/api/tickets/bulk', {
                    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ticket_ids: selectedIds, status: "Assigned Out", comment: "[Rework Required] " + reason, actor: "Analyst" })
                });
                if (res.ok) window.location.reload();
                else { alert("Failed."); this.innerText = `Reject (${selectedIds.length})`; this.disabled = false; }
            } catch(e) { alert("Network error"); this.disabled = false; }
        });
    }
});