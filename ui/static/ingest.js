const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

async function processFile(file) {
    const statusText = document.getElementById('status-text');
    document.getElementById('status-area').classList.remove('d-none');

    const adapterSelect = document.getElementById('adapter-select');
    const adapterId = adapterSelect.value;

    // Safely extract the data-name attribute if an adapter is selected
    let adapterName = "";
    if (adapterSelect.selectedIndex > 0) {
        adapterName = adapterSelect.options[adapterSelect.selectedIndex].getAttribute('data-name');
    }

    try {
        let response;

        // JSON API ROUTE
        if (file.name.toLowerCase().endsWith('.json')) {
            // If no adapter is selected, redirect to Builder instead of throwing an error!
            if (!adapterName) {
                statusText.innerText = "Unknown JSON format. Redirecting to Adapter Builder...";
                setTimeout(() => {
                    window.location.href = `/admin/adapters/new?filename=${encodeURIComponent(file.name)}`;
                }, 1200);
                return; // Halt execution and let the browser redirect
            }

            const rawText = await file.text();
            response = await fetch(`/api/ingest/${encodeURIComponent(adapterName)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: rawText
            });
        }
        // CSV API ROUTE
        else {
            let formData = new FormData();
            formData.append('file', file);
            if (adapterId) {
                formData.append('adapter_id', adapterId);
            }

            response = await fetch('/api/ingest/csv', { method: 'POST', body: formData });
        }

        // Handle the Go Backend Response
        if (!response.ok) {
            if (response.status === 404) {
                statusText.innerText = "Format not recognized. Redirecting to Adapter Builder...";
                setTimeout(() => {
                    window.location.href = `/admin/adapters/new?filename=${encodeURIComponent(file.name)}`;
                }, 1200);
            } else {
                const errText = await response.text();
                throw new Error(errText);
            }
        } else {
            statusText.innerText = "Yeehaw! Tickets corralled successfully.";
            setTimeout(() => window.location.href = "/dashboard", 800);
        }
    } catch (err) {
        statusText.innerText = "Stampede! Error: " + err.message;
    }
}

dropZone.onclick = () => fileInput.click();
fileInput.onchange = (e) => processFile(e.target.files[0]);
dropZone.ondragover = (e) => { e.preventDefault(); dropZone.style.background = "#e1f5fe"; };
dropZone.ondragleave = () => dropZone.style.background = "#f8f9fa";
dropZone.ondrop = (e) => { e.preventDefault(); processFile(e.dataTransfer.files[0]); };