document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const resultPre = document.getElementById('result');
    const spinner = document.getElementById('spinner');

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            resultPre.textContent = 'Please enter a URL.';
            return;
        }

        spinner.style.display = 'block';  // Show spinner
        resultPre.textContent = '';

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });

            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }

            const data = await response.json();

            spinner.style.display = 'none';  // Hide spinner

            resultPre.innerHTML = `
                <strong>Status:</strong> ${data.status} <br>
                <strong>URL:</strong> <a href="${data.url}" target="_blank">${data.url}</a><br>
                <strong>Issues Found:</strong> ${data.issues_found} <br>
                <strong>Message:</strong><br>
                <pre style="margin-top: 5px; font-size: 0.95rem;">${data.message}</pre>
            `;

            const rawSummary = data.summary || 'No summary available';
            document.getElementById('summary').innerHTML = parseBold(rawSummary);



            updateScoreBar(data.score || 0);

        } catch (error) {
            spinner.style.display = 'none';  // Hide spinner
            resultPre.textContent = `❌ Error: ${error.message}`;
            updateScoreBar(0);
        }
    });
});

// 🔧 Score bar updater (with multiple color ranges)
function updateScoreBar(score) {
    const fill = document.getElementById('scoreFill');
    const percent = Math.max(0, Math.min(100, score));
    fill.style.width = percent + '%';
    fill.textContent = ''; // keep text hidden

    // Set color based on score range
    let color = '';

    if (percent >= 90) {
        color = '#00cc44'; // very secure green
    } else if (percent >= 80) {
        color = '#33cc33'; // green
    } else if (percent >= 70) {
        color = '#99cc00'; // yellow-green
    } else if (percent >= 60) {
        color = '#ffcc00'; // yellow
    } else if (percent >= 50) {
        color = '#ff9900'; // orange
    } else if (percent >= 40) {
        color = '#ff6600'; // orange-red
    } else if (percent >= 30) {
        color = '#ff3300'; // red-orange
    } else if (percent >= 20) {
        color = '#ff0000'; // red
    } else {
        color = '#cc0000'; // dark red
    }

    fill.style.backgroundColor = color;
}

document.addEventListener('DOMContentLoaded', () => {
    // existing code ...

    const toggleBtn = document.getElementById('toggle-summary-btn');
    const summaryContainer = document.getElementById('summary-container');
    const closeBtn = document.getElementById('close-summary-btn');

    toggleBtn.addEventListener('click', () => {
        summaryContainer.style.display = 'block';
        toggleBtn.style.display = 'none';
    });

    closeBtn.addEventListener('click', () => {
        summaryContainer.style.display = 'none';
        toggleBtn.style.display = 'block';
    });

    // ... rest of your existing code
});


function parseBold(text) {
    return text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
}

// Usage:
const rawText = "";
const htmlText = parseBold(rawText);
document.getElementById('summary').innerHTML = htmlText;
