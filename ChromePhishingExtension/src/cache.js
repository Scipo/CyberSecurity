const DB_NAME = "DomainReputationCache";
const STORE_NAME = "reputation";
const CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// Open or create the database
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "domain" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Get cached reputation data for a domain
async function getCachedReputation(domain) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(domain);

    request.onsuccess = () => {
      const result = request.result;
      if (result && Date.now() - result.timestamp < CACHE_EXPIRY) {
        resolve(result.data); // Return cached data if not expired
      } else {
        resolve(null); // Return null if cache is expired or not found
      }
    };
    request.onerror = () => reject(request.error);
  });
}

// Cache reputation data for a domain
async function cacheReputation(domain, data) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put({ domain, data, timestamp: Date.now() });

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export { getCachedReputation, cacheReputation };