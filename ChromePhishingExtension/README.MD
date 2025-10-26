# 🛡️ Phishing Website Detector Chrome Extension

A lightweight Chrome extension that detects and warns users about phishing websites in real-time using Google Safe Browsing API.

## ✨ Features
- Real-time phishing website detection
- Uses Google's Safe Browsing API for accurate results
- Simple, non-intrusive warning notifications
- Lightweight and fast performance
- Easy to install and configure

## 🛠️ Installation

### Prerequisites
- Google Chrome or any Chromium-based browser (Edge, Brave, etc.)
- Google API key with Safe Browsing API enable

### Setup Steps
1. **Clone the repository**:
   ```bash
   git clone https://github.com/Scipo/CyberSecurity.git
   cd ChromePhishingExtension
2. **Configure your API key**:
   - Open js/background.js
   - Replace YOUR_API_KEY_HERE with your actual Google API key
3. **Load the extension in Chrome**:
   - Open chrome://extensions/
   - Enable "Developer mode" (toggle in top-right)
   - Click "Load unpacked" and select the extension folder
## 📌 Usage
   - Automatically check every website you visit
   - Show a warning notification if a phishing site is detected
   - Work silently in the background otherwise
## ⚙️ API Configuration
   - Get your API key from Google Cloud Console
   - Enable "Safe Browsing API"
   - (Recommended) Restrict the API key to your extension
