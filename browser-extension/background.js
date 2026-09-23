chrome.webNavigation.onCommitted.addListener((details) => {
    // Only track the main page, not every image, ad, or iframe.
    if (details.frameId !== 0) {
        return;
    }

    const url = new URL(details.url);

    // Only record normal websites.
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return;
    }

    // Don't record Tracker Beta talking to itself.
    if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
        return;
    }

    fetch("http://127.0.0.1:8765/visit", {
        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({
            url: details.url,
            browser: "Chrome"
        })
    })
    .then(async (response) => {
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const result = await response.json();
        console.log("Tracker Beta logged:", result);
    })
    .catch((error) => {
        console.error("Tracker Beta could not log visit:", error);
    });
});

