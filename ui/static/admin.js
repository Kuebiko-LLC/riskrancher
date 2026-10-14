// File: RiskRancher/ui/static/admin.js

function switchTab(tabId, btnElement) {
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    if(btnElement) btnElement.classList.add('active');
}

// --- MAGISTRATE REVIEW LOGIC ---
window.toggleRiskGroup = function(safeAsset) {
    document.querySelectorAll(`.group-${safeAsset}`).forEach(r => {
        r.style.display = r.style.display === "none" ? "table-row" : "none";
    });
};

window.prepMagistrateLink = async function(tokenString, idsString, event) {
    if (event) event.stopPropagation();
    const context = prompt("Context for the approver: what you verified, what you recommend.\n\n(Shown on the approver's page for every finding on this link.)");
    if (!context) return alert("Action cancelled. Give the approver some context.");
    try {
        const ids = idsString.split(',').map(id => parseInt(id, 10)).filter(n => !isNaN(n));
        const res = await fetch('/api/tickets/review-link', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ticket_ids: ids, context: context })
        });
        if (!res.ok) return alert("Failed to mint the approver's link: " + await res.text());
        const data = await res.json();
        const url = window.location.origin + "/review/" + data.token;
        try { await navigator.clipboard.writeText(url); } catch (err) {
            const tempInput = document.createElement("input");
            tempInput.value = url; document.body.appendChild(tempInput); tempInput.select(); document.execCommand("copy"); document.body.removeChild(tempInput);
        }
        alert("Approver's link copied. Send it to the person who signs.");
        window.location.reload();
    } catch (err) { alert("Network error."); }
}

window.denyRisk = async function(id) {
    const comment = prompt("Why is this request denied? (Required; the owner sees it.)");
    if (!comment) return alert("Action cancelled. A reason is required.");
    try {
        const res = await fetch(`/api/tickets/${id}/review`, {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'Deny', comment: comment, extension_days: 0 })
        });
        if (res.ok) window.location.reload(); else alert("Failed: " + await res.text());
    } catch (err) { alert("Network error."); }
}

// --- CONFIG & USERS LOGIC ---
window.deleteUser = async function(id) { if(confirm("Deactivate this user?")) await fetch(`/api/admin/users/${id}`, { method: 'DELETE' }).then(r => r.ok ? window.location.reload() : alert("Failed")); }
window.editRole = async function(id, currentRole) {
    const newRole = prompt("Enter new role (RangeHand, Wrangler, Magistrate, Sheriff):", currentRole);
    if(newRole && newRole !== currentRole) await fetch(`/api/admin/users/${id}/role`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ global_role: newRole }) }).then(r => r.ok ? window.location.reload() : alert("Failed"));
}
window.resetPassword = async function(id) { if(confirm("Generate new password?")) await fetch(`/api/admin/users/${id}/reset-password`, { method: 'PATCH' }).then(async r => r.ok ? alert("New Password: \n\n" + await r.text()) : alert("Failed")); }
window.deleteRule = async function(id) { if(confirm("Delete rule?")) await fetch(`/api/admin/routing/${id}`, { method: 'DELETE' }).then(r => r.ok ? window.location.reload() : alert("Failed")); }
window.loadKEVCatalog = async function() {
    const input = document.getElementById("kevCatalogFile");
    const out = document.getElementById("kevLoadResult");
    if (!input || !input.files.length) return alert("Pick the CISA KEV catalog JSON first.");
    const fd = new FormData();
    fd.append("cisa_catalog_file", input.files[0]);
    out.innerText = "Loading and flagging...";
    const res = await fetch("/api/integrations/cisa/sync", { method: "POST", body: fd });
    if (!res.ok) { out.innerText = "Load failed: " + await res.text(); return; }
    const st = await fetch("/api/integrations/cisa").then(r => r.json());
    out.innerText = `${st.loaded} CVEs loaded, newest ${st.last_added}, flagging ${st.flagged_open} open findings.`;
    const card = document.getElementById("kevCatalogState");
    if (card) card.innerText = `${st.loaded} CVEs loaded, newest ${st.last_added}`;
};

document.addEventListener("DOMContentLoaded", function() {

    // --- LOGS ENGINE ---
    let currentLogPage = 1;
    async function loadLogs() {
        const filter = document.getElementById("logFilter").value;
        const container = document.getElementById("logContainer");
        container.innerHTML = `<div style="text-align: center; color: #3b82f6; padding: 40px; font-weight: bold;">⏳ Fetching Page ${currentLogPage}...</div>`;
        try {
            const res = await fetch(`/api/admin/logs?page=${currentLogPage}&filter=${filter}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            container.innerHTML = "";
            if (!data.feed || data.feed.length === 0) container.innerHTML = `<p style="color: #94a3b8; text-align: center; padding: 40px;">No activity found.</p>`;
            else {
                data.feed.forEach(item => {
                    const badgeStr = item.NewValue ? `<span style="font-family: monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 3px; border: 1px solid #e2e8f0; display: inline-block; margin-top: 4px; font-size: 0.85rem;">${item.NewValue}</span>` : "";
                    container.innerHTML += `<div style="margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px dashed #e2e8f0;"><span style="font-weight: bold; color: #0f172a;">${item.Actor}</span><span style="color: #64748b; font-size: 0.85rem; text-transform: uppercase; margin-left: 5px;">[${item.ActivityType.replace('_', ' ')}]</span><div style="font-size: 0.8rem; color: #94a3b8; float: right;">⏱️ ${item.TimeAgo}</div><br>${badgeStr}</div>`;
                });
            }
            const totalPages = Math.ceil(data.total / data.limit);
            document.getElementById("logPageInfo").innerText = `Showing page ${data.page} of ${totalPages || 1} (Total: ${data.total})`;
            document.getElementById("logPrevBtn").disabled = data.page <= 1;
            document.getElementById("logNextBtn").disabled = data.page >= totalPages;
        } catch (err) { container.innerHTML = `<p style="color: #dc2626; text-align: center; padding: 40px; font-weight: bold;">🚨 Error: ${err.message}</p>`; }
    }

    const logFilter = document.getElementById("logFilter");
    if(logFilter) {
        logFilter.addEventListener("change", () => { currentLogPage = 1; loadLogs(); });
        document.getElementById("logPrevBtn").addEventListener("click", () => { if(currentLogPage > 1) { currentLogPage--; loadLogs(); } });
        document.getElementById("logNextBtn").addEventListener("click", () => { currentLogPage++; loadLogs(); });
        loadLogs();
    }

    // --- UI INITIALIZERS ---
    // Render the Sheriff Risk Tree
    const tbody = document.getElementById("riskTableBody");
    if (tbody) {
        const rows = Array.from(tbody.querySelectorAll("tr.risk-row"));
        if (rows.length === 0) {
            document.getElementById("riskTableHeader").style.display = "table-header-group";
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #94a3b8; padding: 40px;">No pending risk requests.</td></tr>`;
        } else {
            const groups = {};
            rows.forEach(r => {
                const asset = r.getAttribute("data-asset") || "Unknown";
                let typeLabel = "Time Extension"; let typeColor = "#ea580c"; let typeIcon = "⏱️";
                const typeCell = r.querySelector('.risk-type-cell');
                if (typeCell && typeCell.innerText.includes("ACCEPTANCE")) { typeLabel = "Risk Acceptance"; typeColor = "#dc2626"; typeIcon = "🛑"; }
                const groupKey = `${asset}_${typeLabel}`;
                if (!groups[groupKey]) groups[groupKey] = { asset: asset, typeLabel: typeLabel, typeColor: typeColor, typeIcon: typeIcon, rows: [] };
                groups[groupKey].rows.push(r);
            });
            tbody.innerHTML = "";
            for (const key in groups) {
                const group = groups[key];
                const safeKey = key.replace(/[^a-zA-Z0-9-_]/g, '-');
                let unreadCount = group.rows.filter(r => r.innerHTML.includes("✉️ Unread")).length;
                let unreadBadge = unreadCount > 0 ? `<span style="background: #ef4444; color: white; border-radius: 12px; padding: 2px 7px; font-size: 0.75rem; font-weight: bold; margin-left: 10px; animation: pulse 2s infinite;">${unreadCount} Unread</span>` : '';
                const batchTokens = group.rows.map(r => r.getAttribute("data-token")).join(',');
                const batchIDs = group.rows.map(r => r.getAttribute("data-id")).join(',');

                const headerTr = document.createElement("tr");
                headerTr.innerHTML = `<td colspan="5" style="padding: 15px 20px; background: #f8fafc; border-top: 1px solid #cbd5e1; border-bottom: 1px solid #cbd5e1; cursor: pointer;" onclick="toggleRiskGroup('${safeKey}')">
                    <span style="font-family: monospace; font-size: 1.1rem; color: #0f172a; font-weight: bold;">📂 ${group.asset}</span>
                    <span style="background: ${group.typeColor}15; color: ${group.typeColor}; border: 1px solid ${group.typeColor}40; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; margin-left: 10px;">${group.typeIcon} ${group.typeLabel}</span>
                    <span style="color: #64748b; font-size: 0.9rem; margin-left: 5px;">(${group.rows.length} Requests)</span> ${unreadBadge}
                    <button class="btn" style="float: right; padding: 6px 12px; font-size: 0.8rem; background: #2563eb; color: white; margin-left: 15px;" onclick="prepMagistrateLink('${batchTokens}', '${batchIDs}', event)">🔗 Copy Batch Link</button>
                </td>`;
                tbody.appendChild(headerTr);

                const assetDetailsTr = document.createElement("tr");
                assetDetailsTr.className = `group-${safeKey}`; assetDetailsTr.style.display = "none";
                assetDetailsTr.innerHTML = `<td colspan="5" style="padding: 0 20px 20px 40px; position: relative; background: #fafafa;"><div style="position: absolute; left: 25px; top: 0; bottom: 30px; width: 3px; background: ${group.typeColor}; border-radius: 2px;"></div><table style="width: 100%; border-collapse: collapse; margin-top: 10px;"><tbody></tbody></table></td>`;
                tbody.appendChild(assetDetailsTr);
                group.rows.forEach(r => {
                    const indBtn = r.querySelector('button[onclick^="prepMagistrateLink"]');
                    if(indBtn) indBtn.style.display = 'none';
                    assetDetailsTr.querySelector('tbody').appendChild(r);
                });
            }
        }
    }

    // --- SLA MATRIX SAVE ---
    const saveConfigBtn = document.getElementById("saveConfigBtn");
    if(saveConfigBtn) {
        saveConfigBtn.addEventListener("click", async function() {
            this.innerText = "Saving..."; this.disabled = true;
            const payload = {
                timezone: document.getElementById("configTimezone").value,
                business_start: parseInt(document.getElementById("configBizStart").value),
                business_end: parseInt(document.getElementById("configBizEnd").value),
                default_extension_days: parseInt(document.getElementById("configDefExt").value),
                slas: Array.from(document.querySelectorAll(".sla-row")).map(row => ({
                    domain: row.getAttribute("data-domain"),
                    severity: row.querySelector("span.badge").innerText.trim(),
                    days_to_triage: parseInt(row.querySelector(".sla-triage").value),
                    days_to_remediate: parseInt(row.querySelector(".sla-patch").value),
                    max_extensions: parseInt(row.querySelector(".sla-ext").value)
                }))
            };
            const res = await fetch("/api/config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
            if (res.ok) { this.innerText = "Saved!"; this.style.background = "#10b981"; setTimeout(() => { this.innerText = "Save Changes"; this.style.background = ""; this.disabled = false; }, 2000); }
            else { alert("Failed"); this.innerText = "Save Changes"; this.disabled = false; }
        });
    }

    // SLA Domain Filter
    const domainFilter = document.getElementById("slaDomainFilter");
    if (domainFilter) {
        domainFilter.addEventListener("change", function() {
            document.querySelectorAll(".sla-row").forEach(row => row.style.display = row.getAttribute("data-domain") === this.value ? "table-row" : "none");
        });
        domainFilter.dispatchEvent(new Event("change")); // init
    }

    // --- MODAL EVENT LISTENERS ---
    const openUserModal = document.getElementById("openUserModal");
    if (openUserModal) {
        openUserModal.addEventListener("click", () => document.getElementById("userModal").style.display = "flex");
        document.getElementById("cancelUser").addEventListener("click", () => document.getElementById("userModal").style.display = "none");
        document.getElementById("submitUser").addEventListener("click", async function() {
            const payload = { full_name: document.getElementById("newUserName").value, email: document.getElementById("newUserEmail").value, password: document.getElementById("newUserPassword").value, global_role: document.getElementById("newUserRole").value };
            if (!payload.full_name || !payload.email || !payload.password) return alert("Fill out all fields.");
            this.disabled = true;
            await fetch("/api/admin/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).then(async r => r.ok ? window.location.reload() : alert(await r.text()));
            this.disabled = false;
        });
    }

    const newRuleType = document.getElementById("newRuleType");
    if (newRuleType) {
        newRuleType.addEventListener("change", function() {
            document.getElementById("newRuleMatchSource").style.display = this.value === "Source" ? "block" : "none";
            document.getElementById("newRuleMatchAsset").style.display = this.value === "Source" ? "none" : "block";
        });
        document.getElementById("openRuleModal").addEventListener("click", () => document.getElementById("ruleModal").style.display = "flex");
        document.getElementById("cancelRule").addEventListener("click", () => document.getElementById("ruleModal").style.display = "none");
        document.getElementById("submitRule").addEventListener("click", async function() {
            const ruleType = document.getElementById("newRuleType").value;
            const matchVal = ruleType === "Source" ? document.getElementById("newRuleMatchSource").value : document.getElementById("newRuleMatchAsset").value;
            const assigneeSelect = document.getElementById("newRuleAssignee");
            const selectedEmails = Array.from(assigneeSelect.selectedOptions).map(opt => opt.value).join(",");
            if (!matchVal || !selectedEmails) return alert("Fill out match value and assignee.");
            this.disabled = true; this.innerText = "Saving...";
            await fetch("/api/admin/routing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rule_type: ruleType, match_value: matchVal, assignee: selectedEmails, role: "RangeHand" }) }).then(async r => r.ok ? window.location.reload() : alert(await r.text()));
            this.disabled = false; this.innerText = "Deploy Rule";
        });
    }
});