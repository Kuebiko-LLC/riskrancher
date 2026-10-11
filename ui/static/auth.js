document.addEventListener("DOMContentLoaded", () => {

    // --- LOGIN LOGIC ---
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("submitBtn");
            const errDiv = document.getElementById("errorMsg");

            btn.innerText = "Authenticating..."; btn.disabled = true; errDiv.style.display = "none";

            try {
                const res = await fetch("/api/auth/login", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email: document.getElementById("email").value, password: document.getElementById("password").value })
                });

                if (res.ok) window.location.href = "/dashboard";
                else { errDiv.innerText = "Invalid credentials. Please try again."; errDiv.style.display = "block"; btn.innerText = "Sign In"; btn.disabled = false; }
            } catch (err) { errDiv.innerText = "Network error."; errDiv.style.display = "block"; btn.innerText = "Sign In"; btn.disabled = false; }
        });
    }

    // --- REGISTER LOGIC ---
    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("submitBtn");
            const errDiv = document.getElementById("errorMsg");

            btn.innerText = "Securing System..."; btn.disabled = true; errDiv.style.display = "none";

            const payload = {
                full_name: document.getElementById("fullname").value, email: document.getElementById("email").value,
                password: document.getElementById("password").value, global_role: "Sheriff"
            };

            try {
                const res = await fetch("/api/auth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
                if (res.ok) {
                    const loginRes = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: payload.email, password: payload.password }) });
                    if (loginRes.ok) window.location.href = "/dashboard"; else window.location.href = "/login";
                } else {
                    errDiv.innerText = await res.text() || "Registration failed. System might already be locked.";
                    errDiv.style.display = "block"; btn.innerText = "Claim Sheriff Access"; btn.disabled = false;
                }
            } catch (err) { errDiv.innerText = "Network error."; errDiv.style.display = "block"; btn.innerText = "Claim Sheriff Access"; btn.disabled = false; }
        });
    }
});