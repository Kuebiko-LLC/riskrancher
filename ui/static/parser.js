
const reportID = window.location.pathname.split("/").pop();
const clipBtn = document.getElementById('clip-btn');
const viewer = document.getElementById('document-viewer');

window.activeTextarea = null;
document.addEventListener('focusin', function(e) {
    if (e.target && e.target.classList.contains('draft-desc')) {
        window.activeTextarea = e.target;
    }
});

viewer.addEventListener('mouseup', function(e) {
    let selection = window.getSelection();
    let text = selection.toString().trim();

    if (text.length > 5) {
        clipBtn.style.top = `${e.pageY - 50}px`;
        clipBtn.style.left = `${e.pageX - 60}px`;
        clipBtn.style.display = 'block';

        clipBtn.onclick = async () => {
            await saveNewDraft(text);
            clipBtn.style.display = 'none';
            selection.removeAllRanges();
        };
    } else {
        clipBtn.style.display = 'none';
    }
});

document.addEventListener('mousedown', (e) => {
    if (e.target !== clipBtn && !viewer.contains(e.target)) {
        clipBtn.style.display = 'none';
    }
});

viewer.addEventListener('click', async function(e) {
    if (e.target.tagName === 'IMG' && e.target.classList.contains('pentest-img')) {

        const originalBorder = e.target.style.border;
        e.target.style.transition = "border 0.2s, transform 0.2s";
        e.target.style.border = "4px solid #f59e0b";
        e.target.style.transform = "scale(0.98)";

        try {
            const uploadRes = await fetch('/api/images/upload', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ image_data: e.target.src })
            });

            if (!uploadRes.ok) throw new Error("Failed to upload image");
            const data = await uploadRes.json();
            const markdownImage = `![Proof of Concept](${data.url})`;

            if (window.activeTextarea) {
                const start = window.activeTextarea.selectionStart;
                const end = window.activeTextarea.selectionEnd;
                const text = window.activeTextarea.value;

                window.activeTextarea.value = text.substring(0, start) + `\n${markdownImage}\n` + text.substring(end);

                const draftId = window.activeTextarea.getAttribute('data-id');
                updateLivePreview(draftId);
                updateDraftField(draftId);

            } else {
                if (confirm("📸 Extract this screenshot into a BRAND NEW finding?\n\n(Tip: To add it to an existing finding, just click inside its Description box first!)")) {
                    await saveNewDraft(markdownImage);
                }
            }

            e.target.style.border = "4px solid #10b981";
            setTimeout(() => {
                e.target.style.border = originalBorder;
                e.target.style.transform = "scale(1)";
            }, 800);

        } catch (err) {
            console.error(err);
            e.target.style.border = "4px solid #ef4444";
            alert("Error extracting image: " + err.message);
        }
    }
});

async function saveNewDraft(text) {
    try {
        const res = await fetch(`/api/drafts/report/${reportID}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ description: text })
        });
        if (res.ok) loadDrafts();
        else alert("Failed to save draft: " + await res.text());
    } catch (err) {
        alert("Network error saving draft.");
    }
}

window.updateDraftField = function(id) {
    const card = document.querySelector(`.draft-card[data-id="${id}"]`);
    if (!card) return;

    const payload = {
        title: card.querySelector('.draft-title').value,
        asset_identifier: card.querySelector('.draft-asset').value,
        severity: card.querySelector('.draft-severity').value,
        description: card.querySelector('.draft-desc').value,
        recommended_remediation: card.querySelector('.draft-remediation').value
    };

    fetch(`/api/drafts/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    }).catch(e => console.error("Auto-save failed", e));
}

window.renderMarkdown = function(text) {
    if (!text) return "";
    let html = text.replace(/!\[.*?\]\((.*?)\)/g, '<br><img src="$1" style="max-width: 100%; max-height: 200px; object-fit: contain; border: 1px solid #e2e8f0; border-radius: 4px; margin: 10px 0; display: block;"><br>');
    return html;
}

window.updateLivePreview = function(id) {
    const card = document.querySelector(`.draft-card[data-id="${id}"]`);
    if (!card) return;
    const desc = card.querySelector('.draft-desc').value;
    const preview = document.getElementById(`preview-${id}`);

    if (desc.includes('![')) {
        preview.style.display = 'block';
        preview.innerHTML = renderMarkdown(desc);
    } else {
        preview.style.display = 'none';
    }
}

async function loadDrafts() {
    try {
        const res = await fetch(`/api/drafts/report/${reportID}`);
        if (!res.ok) return;
        const drafts = await res.json();

        const list = document.getElementById('draft-list');
        if (!drafts || drafts.length === 0) {
            list.innerHTML = `<div style="text-align: center; color: #94a3b8; margin-top: 40px; font-weight: bold;">No drafts yet.<br><br>Highlight text on the left to begin clipping.</div>`;
            return;
        }

        let html = '';
        drafts.forEach(d => {
            html += `
            <div class="card draft-card" data-id="${d.id}" style="margin-bottom: 20px; padding: 15px; border: 1px solid #cbd5e1; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background: white;">
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <input type="text" class="draft-title" onchange="updateDraftField(${d.id})" placeholder="Finding Title (Required)" value="${d.title || ''}" style="flex: 2; padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; font-weight: bold; color: #0f172a;">
                    <select class="draft-severity" onchange="updateDraftField(${d.id})" style="flex: 1; padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; background: white; color: #0f172a;">
                        <option value="Critical" ${d.severity === 'Critical' ? 'selected' : ''}>Critical</option>
                        <option value="High" ${d.severity === 'High' ? 'selected' : ''}>High</option>
                        <option value="Medium" ${d.severity === 'Medium' ? 'selected' : 'selected'}>Medium</option>
                        <option value="Low" ${d.severity === 'Low' ? 'selected' : ''}>Low</option>
                        <option value="Info" ${d.severity === 'Info' ? 'selected' : ''}>Info</option>
                    </select>
                </div>
                <div style="margin-bottom: 10px;">
                    <input type="text" class="draft-asset" onchange="updateDraftField(${d.id})" placeholder="Asset Identifier (e.g. api.ranch.com) (Required)" value="${d.asset_identifier || ''}" style="width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; color: #0f172a;">
                </div>
                <div style="margin-bottom: 10px;">
                    <label style="font-size: 0.75rem; font-weight: bold; color: #64748b;">Description (Markdown Images Supported)</label>
                    <textarea class="draft-desc" data-id="${d.id}" onkeyup="updateLivePreview(${d.id}); updateDraftField(${d.id})" onchange="updateDraftField(${d.id})" placeholder="Vulnerability Description..." style="width: 100%; height: 80px; padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.85rem; font-family: inherit; resize: vertical; color: #334155;">${d.description || ''}</textarea>
                    
                    <div id="preview-${d.id}" style="margin-top: 5px; padding: 10px; background: #f8fafc; border: 1px dashed #94a3b8; border-radius: 4px; display: ${d.description && d.description.includes('![') ? 'block' : 'none'}; max-height: 250px; overflow-y: auto; resize: vertical;">
                        ${renderMarkdown(d.description || '')}
                    </div>
                </div>
                <div style="margin-bottom: 10px;">
                    <textarea class="draft-remediation" onchange="updateDraftField(${d.id})" placeholder="Recommended Remediation..." style="width: 100%; height: 60px; padding: 8px; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.85rem; font-family: inherit; resize: vertical; color: #334155;">${d.recommended_remediation || ''}</textarea>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px dashed #e2e8f0; padding-top: 10px;">
                    <button class="btn" style="padding: 4px 10px; font-size: 0.75rem; color: #0284c7; background: #e0f2fe; border: 1px solid #7dd3fc;" data-text="${encodeURIComponent(d.description || '')}" onclick="smartSnap(this)">📍 Snap to Text</button>
                    <button class="btn" style="padding: 4px 10px; font-size: 0.75rem; color: #dc2626; background: #fee2e2; border: 1px solid #fca5a5;" onclick="deleteDraft(${d.id})">🗑️ Discard</button>
                </div>
            </div>`;
        });
        list.innerHTML = html;
    } catch (err) {
        console.error("Failed to load drafts", err);
    }
}

window.deleteDraft = async function(id) {
    if (!confirm("Discard this finding?")) return;
    try {
        const res = await fetch(`/api/drafts/${id}`, { method: 'DELETE' });
        if (res.ok) loadDrafts();
    } catch (err) {
        alert("Error discarding draft.");
    }
}

window.promoteAllDrafts = async function() {
    const cards = document.querySelectorAll('.draft-card');
    if (cards.length === 0) return alert("No drafts to promote!");

    const payload = [];
    let hasError = false;

    cards.forEach(card => {
        const id = parseInt(card.getAttribute('data-id'));
        const titleInput = card.querySelector('.draft-title');
        const assetInput = card.querySelector('.draft-asset');

        const title = titleInput.value.trim();
        const asset = assetInput.value.trim();
        const severity = card.querySelector('.draft-severity').value;
        const description = card.querySelector('.draft-desc').value.trim();
        const remediation = card.querySelector('.draft-remediation').value.trim();

        if (!title || !asset) {
            if (!title) titleInput.style.borderColor = '#dc2626';
            if (!asset) assetInput.style.borderColor = '#dc2626';
            hasError = true;
        }

        payload.push({ id, title, asset_identifier: asset, severity, description, recommended_remediation: remediation });
    });

    if (hasError) return alert("🚨 Title and Asset Identifier are required.");

    try {
        const res = await fetch(`/api/reports/promote/${reportID}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            alert("🤠 Yeehaw! Findings promoted to your Holding Pen.");
            window.location.href = "/dashboard";
        } else {
            alert("Failed to promote: " + await res.text());
        }
    } catch (err) {
        alert("Network error during promotion.");
    }
}

window.smartSnap = function(btnElement) {
    const viewer = document.getElementById('document-viewer');
    const fullText = decodeURIComponent(btnElement.getAttribute('data-text'));

    const searchStr = fullText.split('\n')[0].substring(0, 30).trim();
    if (!searchStr || searchStr.startsWith("![")) return alert("Cannot snap to image blocks.");

    const paragraphs = viewer.getElementsByTagName('p');
    let foundElement = null;

    for (let p of paragraphs) {
        if (p.innerText.length > 50 && p.innerText.includes(searchStr)) {
            foundElement = p;
            break;
        }
    }

    if (foundElement) {
        foundElement.scrollIntoView({ behavior: "smooth", block: "center" });
        const originalBg = foundElement.style.backgroundColor;
        foundElement.style.transition = "background-color 0.4s";
        foundElement.style.backgroundColor = "#bfdbfe";
        setTimeout(() => foundElement.style.backgroundColor = originalBg, 1200);

        const originalText = btnElement.innerText;
        btnElement.innerText = "🎯 Snapped!";
        setTimeout(() => btnElement.innerText = originalText, 1500);
    } else {
        alert("Could not locate the exact paragraph body in the document.");
    }
}

document.addEventListener("DOMContentLoaded", loadDrafts);