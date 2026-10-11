window.showUpsell = function(featureName) {
    document.getElementById('upsellFeatureName').innerText = featureName;
    document.getElementById('upsellModal').style.display = 'flex';
};

function switchTab(tabId, btnElement) {
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    if(btnElement) btnElement.classList.add('active');
}


// --- CONFIG & USERS LOGIC ---
window.deleteUser = async function(id) { if(confirm("Deactivate this user?")) await fetch(`/api/admin/users/${id}`, { method: 'DELETE' }).then(r => r.ok ? window.location.reload() : alert("Failed")); }
window.editRole = async function(id, currentRole) {
    const newRole = prompt("Enter new role (RangeHand, Wrangler, Magistrate, Sheriff):", currentRole);
    if(newRole && newRole !== currentRole) await fetch(`/api/admin/users/${id}/role`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ global_role: newRole }) }).then(r => r.ok ? window.location.reload() : alert("Failed"));
}
window.resetPassword = async function(id) { if(confirm("Generate new password?")) await fetch(`/api/admin/users/${id}/reset-password`, { method: 'PATCH' }).then(async r => r.ok ? alert("New Password: \n\n" + await r.text()) : alert("Failed")); }
window.deleteRule = async function(id) { if(confirm("Delete rule?")) await fetch(`/api/admin/routing/${id}`, { method: 'DELETE' }).then(r => r.ok ? window.location.reload() : alert("Failed")); }
window.updateBackupPolicy = async function() { const pol = document.getElementById("backupPolicy").value; await fetch(`/api/admin/backup-policy`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policy: pol }) }).then(r => r.ok ? alert("Saved") : alert("Failed")); }
window.checkUpdates = async function() { await fetch(`/api/admin/check-updates`).then(async r => alert(await r.text())); }

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
    document.querySelectorAll('.risk-row').forEach(row => {
        const rationaleDiv = row.querySelector('.risk-rationale-cell');
        const typeCell = row.querySelector('.risk-type-cell');
        if (!rationaleDiv || !typeCell) return;
        let text = rationaleDiv.innerText.trim();
        if (text.includes('[EXTENSION]')) {
            typeCell.innerHTML = '<span style="background: #ffedd5; color: #ea580c; border: 1px solid #fdba74; padding: 6px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: bold;">⏱️ TIME EXTENSION</span>';
            rationaleDiv.innerText = text.replace('[EXTENSION]', '').trim();
            rationaleDiv.style.borderLeft = "3px solid #ea580c";
        } else if (text.includes('[RISK ACCEPTANCE]')) {
            typeCell.innerHTML = '<span style="background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; padding: 6px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: bold;">🛑 RISK ACCEPTANCE</span>';
            rationaleDiv.innerText = text.replace('[RISK ACCEPTANCE]', '').trim();
            rationaleDiv.style.borderLeft = "3px solid #dc2626";
            row.style.backgroundColor = "#fff5f5";
        } else {
            typeCell.innerHTML = '<span style="background: #f1f5f9; color: #64748b; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: bold;">📋 STANDARD</span>';
        }
    });


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
        domainFilter.dispatchEvent(new Event("change"));
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