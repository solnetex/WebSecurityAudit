const form = document.getElementById('scanForm');
const output = document.getElementById('output');

form.addEventListener('submit', async (e) => {
    e.preventDefault(); // stop form from reloading the page

    const url = document.getElementById('url').value;
    output.textContent = "🔎 Scanning... please wait.";

    try {
        // Send to backend (replace with real URL later)
        const response = await fetch('http://127.0.0.1:5000', {

            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const result = await response.json();
        output.textContent = `✅ Scan Complete:\n\n${JSON.stringify(result, null, 2)}`;
    } catch (err) {
        output.textContent = `❌ Error: Could not scan the website.\n\n${err.message}`;
    }
});
