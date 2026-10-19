// Shared UI helpers, loaded on every page before the per-page scripts.

// esc HTML-escapes a value before it is interpolated into innerHTML, so ingested
// data (finding titles, asset names, descriptions, actor emails) cannot carry markup
// into the page. Any script that builds HTML from server/ingested data must run each
// field through this first. Server data is safe in attributes and textContent; it is
// only dangerous when concatenated into an HTML string.
window.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
};
