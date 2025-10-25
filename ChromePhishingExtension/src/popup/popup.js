// Get the current tab's URL and send it to the background script for analysis
document.addEventListener("DOMContentLoaded", () => {

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0) {
      const url = tabs[0].url;
      chrome.runtime.sendMessage({ action: "analyzeUrl", url }, (response) => {
        const resultDiv = document.getElementById("result");
        if (chrome.runtime.lastError) {
          resultDiv.innerHTML = `<p style="color: red;">Error: ${chrome.runtime.lastError.message}</p>`;
          return;
        }
        if (response && response.isPhishing) {
          resultDiv.innerHTML = `
            <p style="color: red;"> Warning: This website may be a phishing site!</p>
            <p>Reason: ${response.reason}</p>
          `;
        } else if (response) {
          resultDiv.innerHTML = `
            <p style="color: green;"> This website appears to be safe.</p>
          `;
        } else {
          resultDiv.innerHTML = `<p style="color: red;">Error: No response from background script.</p>`;
        }
      });
    } else {
      const resultDiv = document.getElementById("result");
      resultDiv.innerHTML = `<p style="color: red;">Error: No active tab found.</p>`;
    }
  });
});


