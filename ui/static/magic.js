// File: RiskRancher/ui/static/magic.js

(function() {
    const pathParts = window.location.pathname.split('/');
    const currentToken = pathParts[pathParts.length - 1];
// ==========================================
    // ⚖️ MAGISTRATE (LEGAL/COMPLIANCE) LOGIC
    // ==========================================
    window.renderMagistrate = function(data) {
        // Filter for ONLY tickets pending risk approval
        const riskTickets = data.tickets.filter(t => (t.Status || t.status) === 'Pending Risk Approval');
        if (riskTickets.length === 0) throw new Error("InboxZero");

        const first = riskTickets[0];
        document.getElementById('magAsset').innerText = first.AssetIdentifier || first.asset_identifier || "Multiple Assets";
        document.getElementById('magFindingCount').innerText = riskTickets.length;

        // Populate the list of findings
        const list = document.getElementById('magFindingsList');
        list.innerHTML = "";
        riskTickets.forEach(t => {
            const div = document.createElement('div');
            div.style.padding = "10px";
            div.style.borderBottom = "1px solid #e2e8f0";
            const sev = (t.Severity || t.severity).toLowerCase();
            div.innerHTML = `<strong>${t.Title || t.title}</strong> <span class="badge ${sev}">${t.Severity || t.severity}</span><br><span style="font-size:0.85rem;color:#64748b;">${t.Description || t.description}</span>`;
            list.appendChild(div);
        });

        // The days field starts from the configured default
        const daysInput = document.getElementById('extensionDays');
        if (daysInput && data.default_extension_days) daysInput.value = data.default_extension_days;

        // Populate the context boxes
        document.getElementById('magITReason').innerText = first.RiskRationale || first.risk_rationale || "No rationale provided by IT.";
        document.getElementById('magSheriffReason').innerText = first.LatestComment || first.latest_comment || "No context provided by Security.";
    };

    window.submitAdjudication = async function(action) {
        const comment = document.getElementById('magistrateComment').value.trim();
        const days = parseInt(document.getElementById('extensionDays').value, 10);

        if (action === 'Deny' && !comment) return alert("A comment is strictly required to Deny a request for audit purposes.");

        const btn = document.getElementById('magApproveBtn');
        if (btn) btn.disabled = true;

        try {
            // Hit the Magistrate Review Endpoint
            const res = await fetch(`/api/share/${currentToken}/review`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, actor: "Legal / Compliance", comment: comment, extension_days: isNaN(days) ? 0 : days })
            });

            if (res.ok) {
                alert(`✅ Exception ${action}ed successfully.`);
                window.location.reload();
            } else {
                alert("Failed to submit review: " + await res.text());
                if (btn) btn.disabled = false;
            }
        } catch (e) {
            alert("Network error: " + e.message);
            if (btn) btn.disabled = false;
        }
    };
    async function init() {
        try {
            const isApprover = !!document.getElementById('magAsset');
            const res = isApprover ? await fetch(`/api/share/${currentToken}/review`) : await fetch(`/api/share/${currentToken}`);
            if (!res.ok) throw new Error("This link is no longer valid.");
            const data = await res.json();

            const ticketList = document.getElementById('ticketList');
            if (ticketList) {
                // Filter the list so the Wrangler ONLY sees their pending tasks
                data.tickets = data.tickets.filter(t => (t.Status || t.status) === 'Assigned Out');

                // If they've processed everything, trigger the custom Success Screen!
                if (data.tickets.length === 0) throw new Error("InboxZero");

                renderWranglerTree(data);
                document.getElementById("assigneeName").innerText = data.assignee || "IT Wrangler";
            } else if (document.getElementById('magAsset')) {
                // The Magistrate UI will render everything the backend sent (Pending Risk, etc.)
                renderMagistrate(data);
            }
        } catch (err) {
            // Beautiful contextual error/success screens!
            if (err.message === "InboxZero") {
                document.body.innerHTML = `
                    <div style="text-align:center; padding: 100px; max-width: 600px; margin: 0 auto;">
                        <h1 style="font-size: 4rem; margin-bottom: 10px;">🤠</h1>
                        <h2 style="color: #0f172a;">All Done Here!</h2>
                        <p style="color: #64748b; font-size: 1.1rem;">This assignment has been fully completed, returned, or routed to Legal. You can safely close this window.</p>
                    </div>`;
            } else {
                document.body.innerHTML = `<div style="text-align:center; padding: 100px;"><h2>🚨 Token Error</h2><p>${err.message}</p></div>`;
            }
        }
    }
    function renderWranglerTree(data) {
        const tbody = document.getElementById("ticketList");
        const assets = {};
        data.tickets.forEach(t => {
            const asset = t.AssetIdentifier || t.asset_identifier || "Unknown Asset";
            if (!assets[asset]) assets[asset] = [];
            assets[asset].push(t);
        });

        tbody.innerHTML = "";
        Object.keys(assets).forEach(assetName => {
            const findings = assets[assetName];
            const safeId = btoa(assetName).replace(/=/g, ''); // Unique ID for folding

            // Asset Folder Row
            const hRow = document.createElement("tr");
            hRow.className = "asset-header-row";
            hRow.style.background = "#fff";
            hRow.style.borderBottom = "1px solid #e2e8f0";
            hRow.innerHTML = `
                <td style="padding: 15px 20px; width: 40px;"><input type="checkbox" class="asset-cb" data-target="${safeId}"></td>
                <td colspan="4" style="padding: 15px; cursor: pointer; font-weight: bold;" onclick="toggleFolder('${safeId}')">
                    📂 ${assetName} <span style="color: #64748b; font-weight: normal; margin-left: 10px;">(${findings.length} findings)</span>
                </td>
            `;
            tbody.appendChild(hRow);

            // Container for findings
            const dRow = document.createElement("tr");
            dRow.id = `folder-${safeId}`;
            dRow.style.display = "none";
            dRow.innerHTML = `
                <td colspan="5" style="padding: 0 0 10px 60px; background: #fcfcfc;">
                    <table style="width: 100%; border-left: 3px solid #cbd5e1;">
                        <tbody id="body-${safeId}"></tbody>
                    </table>
                </td>
            `;
            tbody.appendChild(dRow);

            const innerBody = document.getElementById(`body-${safeId}`);
// Use the actual Ticket ID so the backend knows what to update!
            findings.forEach(f => {
                const tr = document.createElement("tr");
                const sev = (f.Severity || f.severity || "info").toLowerCase();
                tr.innerHTML = `
                    <td style="padding: 8px 20px; width: 30px;"><input type="checkbox" class="ticket-cb" value="${f.ID || f.id}"></td>
                    <td style="width: 80px;"><span class="badge ${sev}">${sev}</span></td>
                    <td>${f.Title || f.title}</td>
                    <td style="color: #64748b; font-size: 0.8rem;">${f.Status || f.status}</td>
                `;
                innerBody.appendChild(tr);
            });

            // Folder bulk checkbox logic
            hRow.querySelector(".asset-cb").addEventListener("change", function() {
                innerBody.querySelectorAll(".ticket-cb").forEach(cb => cb.checked = this.checked);
            });
        });
    }

    window.toggleFolder = function(id) {
        const row = document.getElementById(`folder-${id}`);
        row.style.display = (row.style.display === "none") ? "table-row" : "none";
    };

    // --- REJECT MODAL LOGIC ---
    document.getElementById("rejectBtn")?.addEventListener("click", () => {
        const checked = document.querySelectorAll(".ticket-cb:checked");
        if (checked.length === 0) return alert("Select at least one finding to return.");
        document.getElementById("rejectModal").style.display = "flex";
    });



    // --- REJECT TRAP LOGIC ---
    document.getElementById("confirmRejectBtn")?.addEventListener("click", async function() {
        const reason = document.getElementById("rejectReason").value;
        const comment = document.getElementById("rejectComment").value.trim();

        // 1. Grab the checked boxes
        const selected = document.querySelectorAll(".ticket-cb:checked");

        if (!comment) return alert("Comment is mandatory.");

        // 2. Extensively debug the values
        const ids = [];
        const rawValues = [];
        selected.forEach(cb => {
            rawValues.push(cb.value);
            const parsed = parseInt(cb.value, 10);
            if (!isNaN(parsed)) ids.push(parsed);
        });

        // 🚨 THE TRAP: If the array is empty, freeze and display the evidence!
        if (ids.length === 0) {
            alert(`🚨 FRONTEND TRAP TRIGGERED!\n\nCheckboxes Found: ${selected.length}\nRaw Checkbox Values: ${JSON.stringify(rawValues)}\n\nIf Checkboxes = 0, the DOM is losing your clicks. If Raw Values are empty or "undefined", the HTML rendering is broken!`);
            return; // Stop the script from hitting the Go backend
        }

        this.disabled = true; this.innerText = "Returning...";

        try {
            const payload = { ticket_ids: ids, reason: reason, comment: comment };
            const res = await fetch(`/api/share/${currentToken}/reject`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                alert("Returned to Security Team.");
                window.location.reload();
            } else {
                alert("Failed to return: " + await res.text());
                this.disabled = false; this.innerText = "Confirm & Return";
            }
        } catch (e) {
            alert("Error: " + e.message);
            this.disabled = false; this.innerText = "Confirm & Return";
        }
    });

    // --- SUBMIT TRAP LOGIC ---
    document.getElementById("submitBtn")?.addEventListener("click", async function() {
        const checked = document.querySelectorAll(".ticket-cb:checked");
        const evidence = document.getElementById("evidenceText").value.trim();

        if (checked.length === 0) return alert("Select at least one finding to submit a fix for.");
        if (!evidence) return alert("Submission evidence is mandatory to verify the patch.");

        const ids = [];
        const rawValues = [];
        checked.forEach(cb => {
            rawValues.push(cb.value);
            const parsed = parseInt(cb.value, 10);
            if (!isNaN(parsed)) ids.push(parsed);
        });

        // 🚨 THE TRAP
        if (ids.length === 0) {
            alert(`🚨 FRONTEND TRAP TRIGGERED!\n\nCheckboxes Found: ${checked.length}\nRaw Checkbox Values: ${JSON.stringify(rawValues)}`);
            return;
        }

        this.disabled = true; this.innerText = "Submitting...";

        try {
            const payload = { ticket_ids: ids, patch_evidence: evidence, status: "Pending Verification" };
            const res = await fetch(`/api/share/${currentToken}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                alert("✅ Fix submitted successfully! The Security Team will verify it.");
                window.location.reload();
            } else {
                alert("Failed to submit fix: " + await res.text());
                this.disabled = false; this.innerText = "Submit Fix for Selected";
            }
        } catch (e) {
            alert("Network error: " + e.message);
            this.disabled = false; this.innerText = "Submit Fix for Selected";
        }
    });

    // --- REQUEST EXCEPTION LOGIC ---
    document.getElementById("openRiskModalBtn")?.addEventListener("click", async function() {
        const checked = document.querySelectorAll(".ticket-cb:checked");
        if (checked.length === 0) return alert("Select at least one finding to request an exception for.");
        const ids = Array.from(checked).map(cb => parseInt(cb.value, 10));
        const kind = document.getElementById("riskKind")?.value || "Time Extension";

        const rationale = prompt(kind === "Risk Acceptance"
            ? "Why should this risk be accepted, and what compensating control is in place? (Required for review)"
            : "Why is more time needed, and when will the fix land? (Required for review)");
        if (!rationale) return alert("Action cancelled. A rationale is strictly required.");

        this.disabled = true;
        this.innerText = "Requesting...";

        try {
            const res = await fetch(`/api/share/${currentToken}/risk`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ticket_ids: ids, type: kind, rationale: rationale })
            });

            if (res.ok) {
                alert("⚖️ Request sent. It is now waiting for the risk approver.");
                window.location.reload();
            } else {
                alert("Failed to request exception: " + await res.text());
                this.disabled = false; this.innerText = "⚖️ Request Exception";
            }
        } catch (e) {
            alert("Network error: " + e.message);
            this.disabled = false; this.innerText = "⚖️ Request Exception";
        }
    });
    init();
})();