const whitelistElement = document.getElementById("whitelist");
// Extract the blocked URL from the query parameter
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url');
document.getElementById('blocked-url').textContent = blockedUrl;

// Go back to the previous page
document.getElementById('back-button').addEventListener('click', () => {
  window.history.back();
});

// Handle false positive reporting
document.getElementById('report-button').addEventListener('click', () => {
  console.log("This is block : ", blockedUrl);
  const domain = blockedUrl;
  if (domain) {
    chrome.storage.sync.get("whitelist", (data) => {
      const whitelist = data.whitelist || [];
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.sync.set({ whitelist }, () => {
           //updateWhitelistUI(whitelist);
        });
      }
    });
  }
});

