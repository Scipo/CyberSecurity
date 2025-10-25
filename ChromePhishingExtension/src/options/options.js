const domainInput = document.getElementById("domainInput");
const addButton = document.getElementById("addButton");
const whitelistElement = document.getElementById("whitelist");

const logsElements = document.getElementById("logs");
const clearLogs = document.getElementById("clear-logs");
const LOG_STORAGE_KEY = "blockedUrlsLog";

function loadWhitelist() {
  chrome.storage.sync.get("whitelist", (data) => {
    const whitelist = data.whitelist || [];
    updateWhitelistUI(whitelist);
  });
}

// Add a domain to the whitelist
addButton.addEventListener("click", () => {
  const domain = domainInput.value.trim();
  if (domain) {
    chrome.storage.sync.get("whitelist", (data) => {
      const whitelist = data.whitelist || [];
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.sync.set({ whitelist }, () => {
          updateWhitelistUI(whitelist);
          domainInput.value = "";
        });
      }
    });
  }
});

//Remove a domain from the whitelist
function removeDomain(domain) {
  chrome.storage.sync.get("whitelist", (data) => {
    const whitelist = data.whitelist || [];
    const updatedWhitelist = whitelist.filter((item) => item !== domain);
    chrome.storage.sync.set({ whitelist: updatedWhitelist }, () => {
      updateWhitelistUI(updatedWhitelist);
    });
  });
}

// Update the whitelist UI
function updateWhitelistUI(whitelist) {
  whitelistElement.innerHTML = whitelist
    .map(
      (domain) => `
         <li>
            <p>${domain}</p>
            <button class="button-55" id="remove-button" data-domain="${domain}">Remove</button>
        </li>
    `
    )
    .join("");

  // Add event listeners to remove buttons
  document.querySelectorAll("#remove-button").forEach((button) => {
    button.addEventListener("click", () => {
      const domain = button.getAttribute("data-domain");
      removeDomain(domain);
    });
  });
}

// Load the whitelist when the page loads
loadWhitelist();

// Load and display logs
function loadLogs(){
  chrome.storage.local.get(LOG_STORAGE_KEY, (data) => {
    const logs = data[LOG_STORAGE_KEY] || [];
    const formattedLogs = logs.map(log => 
      `[${log.timestamp}] ${log.url} - Reason: ${log.reason}`
    ).join("\n");
    logsElements.textContent = formattedLogs;
  });
}

//clear logs
clearLogs.addEventListener("click", () => {
  chrome.storage.local.set({ [LOG_STORAGE_KEY]: [] }, () => {
    logsElements.textContent = "Logs cleared.";
  });
});

loadLogs();