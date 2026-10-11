async function uploadScan() {
    const fileInput = document.getElementById('scanFile');
    const adapterSelect = document.getElementById('adapterSelect');
    const resultDiv = document.getElementById('ingestResult');

    const file = fileInput.files[0];
    const adapterName = adapterSelect.value;

    if (!file) {
        showResult("Please select a file to upload.", false);
        return;
    }

    if (!adapterName) {
        showResult("Please select an adapter.", false);
        return;
    }

    // Show processing state
    showResult("Processing...", true, true);

    try {
        let response;

        // Route appropriately based on file extension
        if (file.name.toLowerCase().endsWith('.json')) {
            const rawText = await file.text();
            response = await fetch(`/api/ingest/${encodeURIComponent(adapterName)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: rawText
            });
        } else {
            let formData = new FormData();
            formData.append('file', file);
            formData.append('adapter_name', adapterName); // Pass adapter name for CSVs

            response = await fetch('/api/ingest/csv', { method: 'POST', body: formData });
        }

        if (!response.ok) {
            // Auto-redirect to builder if the adapter doesn't match the file structure
            if (response.status === 404) {
                showResult("Format not recognized. Redirecting to Adapter Builder...", false);
                setTimeout(() => {
                    window.location.href = `/admin/adapters/new?filename=${encodeURIComponent(file.name)}`;
                }, 1200);
            } else {
                const errText = await response.text();
                throw new Error(errText);
            }
        } else {
            showResult("Yeehaw! Tickets corralled successfully.", true);
            setTimeout(() => window.location.href = "/dashboard", 1000);
        }
    } catch (err) {
        showResult("Stampede! Error: " + err.message, false);
    }
}

// Helper function to handle status messages nicely
function showResult(msg, isSuccess, isInfo = false) {
    const div = document.getElementById('ingestResult');
    div.style.display = 'block';
    div.innerText = msg;

    if (isInfo) {
        div.style.backgroundColor = '#e0f2fe';
        div.style.color = '#0369a1';
        div.style.border = '1px solid #bae6fd';
    } else if (isSuccess) {
        div.style.backgroundColor = '#dcfce7';
        div.style.color = '#166534';
        div.style.border = '1px solid #bbf7d0';
    } else {
        div.style.backgroundColor = '#fee2e2';
        div.style.color = '#991b1b';
        div.style.border = '1px solid #fecaca';
    }
}