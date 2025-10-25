import { getCachedReputation, cacheReputation } from "./cache.js";

const MAX_LOG_ENTRIES = 100;
const WHITELIST_STORAGE_KEY = "whitelist";
const LOG_STORAGE_KEY = "blockedUrlsLog";


let whitelist = [];

// Initialize whitelist
chrome.storage.sync.get(WHITELIST_STORAGE_KEY, (data) => {
  console.log("Initialize whitelist");
  whitelist = data[WHITELIST_STORAGE_KEY] || [];
});

// Track whitelist changes
chrome.storage.onChanged.addListener((changes) => {
  if (changes[WHITELIST_STORAGE_KEY]) {
    whitelist = changes[WHITELIST_STORAGE_KEY].newValue;
  }
});

// check if a url is in the whitelist
function isWhitelisted(url){
  console.log("check if a url is in the whitelist"); 
  //const domain = new URL(url).hostname;
  return whitelist.some((whitelisted) => url.includes(whitelisted));
}

async function logBlockedUrl(url, reason) {
   const logEntry = {
    url,
    reason,
    timestamp : new Date().toISOString(),
   };
  
   // Add new log entry and limit to MAX_LOG_ENTRIES
   const {[LOG_STORAGE_KEY] : logs = []} = await chrome.storage.local.get(LOG_STORAGE_KEY);
   const updatedLog = [...logs, logEntry].slice(-MAX_LOG_ENTRIES);

   //Save Log
   await chrome.storage.local.set({[LOG_STORAGE_KEY] : updatedLog});
   console.log("Log blockerd URL:", logEntry);

}

// Function to check domain reputation using Google Safe Browsing API
async function checkGoogleSafeBrowsing(url) {
  const domain = new URL(url).hostname;

  // Check cache first
  const cachedResult = await getCachedReputation(domain);
  if (cachedResult) {
    console.log("Using cached result for:", domain);
    return cachedResult;
  }

  // If not cached, make an API call
  const API_KEY= "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"; 
  const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
  // Validate URL format
  try {
    new URL(url); // Throws an error for invalid URLs
  } catch (error) {
    console.error("Invalid URL:", url);
    return false; // Treat invalid URLs as safe
  }

  // Validate API key
  if (!API_KEY || API_KEY === "YOUR_GOOGLE_SAFE_BROWSING_API_KEY") {
    console.error("Missing or invalid Google Safe Browsing API key.");
    return false;
  }

  const requestBody = {
    client: { clientId: "phishing-detector-extension", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      // Handle specific HTTP errors
      let errorMessage;
      switch (response.status) {
        case 400:
          errorMessage = "Bad request (invalid parameters).";
          break;
        case 403:
          errorMessage = "API key is invalid or unauthorized.";
          break;
        case 429:
          errorMessage = "API quota exceeded.";
          break;
        default:
          errorMessage = `HTTP error! Status: ${response.status}`;
      }
      throw new Error(errorMessage);
    }

    const data = await response.json();
    cacheReputation(domain, data);
    return data.matches ? true : false;

  } catch (error) {
    return false; // Assume safe on error
  }
}


//Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeUrl") {
    const url = request.url;

    // Check if the URL is in the whitelist
    if (isWhitelisted(url)) {
      sendResponse({ isPhishing: false, reason: "" });
      return true; 
    }else{
      checkGoogleSafeBrowsing(url).then((isUnsafe) => {
        console.log(isUnsafe, " ana");
        if (isUnsafe == true) {
            sendResponse({ isPhishing: true, reason: "google_safe_browsing" });
        } else {
          sendResponse({ isPhishing: false, reason: "" });
        }
      });
    } 
    return true; 
  }
});

// Redirect to blocked.html if the URL is unsafe
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  const url = details.url;
  const isUnsafe = await checkGoogleSafeBrowsing(url);
  console.log(isUnsafe);
  // Skip if the URL is in the whitelist
  if (isWhitelisted(url)){
    console.log("This is a test for whitelist");
    return;
  }else{
    if (isUnsafe == true) {
      console.log(isUnsafe);
      logBlockedUrl(url, "google_safe_browsing");
      console.log(`Blocked unsafe URL: ${url}`);
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL("blocked/blocked.html") + `?url=${encodeURIComponent(url)}`
      });
    }
  }
  
  
   
}, { url: [{ schemes: ["http", "https"] }] });
