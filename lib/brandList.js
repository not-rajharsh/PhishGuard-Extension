// lib/brandList.js
// A curated list of high-value phishing-target brands and their legitimate
// root domains. Used to detect lookalike / typosquatted domains.
// This is intentionally NOT exhaustive -- it targets the most commonly
// impersonated categories: finance, payments, email/cloud, e-commerce,
// crypto, and shipping/logistics (frequently used in phishing lures).

const KNOWN_BRANDS = [
  // Payments / Finance
  { name: "PayPal", domain: "paypal.com" },
  { name: "Visa", domain: "visa.com" },
  { name: "Mastercard", domain: "mastercard.com" },
  { name: "American Express", domain: "americanexpress.com" },
  { name: "Chase", domain: "chase.com" },
  { name: "Bank of America", domain: "bankofamerica.com" },
  { name: "Wells Fargo", domain: "wellsfargo.com" },
  { name: "Citibank", domain: "citi.com" },
  { name: "Capital One", domain: "capitalone.com" },
  { name: "HSBC", domain: "hsbc.com" },
  { name: "Revolut", domain: "revolut.com" },
  { name: "Stripe", domain: "stripe.com" },
  { name: "Venmo", domain: "venmo.com" },
  { name: "Zelle", domain: "zellepay.com" },
  { name: "Intuit", domain: "intuit.com" },
  { name: "Chime", domain: "chime.com" },

  // Crypto
  { name: "Coinbase", domain: "coinbase.com" },
  { name: "Binance", domain: "binance.com" },
  { name: "Kraken", domain: "kraken.com" },
  { name: "MetaMask", domain: "metamask.io" },
  { name: "Ledger", domain: "ledger.com" },
  { name: "Trezor", domain: "trezor.io" },

  // Tech / Cloud / Email
  { name: "Google", domain: "google.com" },
  { name: "Gmail", domain: "gmail.com" },
  { name: "Microsoft", domain: "microsoft.com" },
  { name: "Outlook", domain: "outlook.com" },
  { name: "Office365", domain: "office.com" },
  { name: "Apple", domain: "apple.com" },
  { name: "iCloud", domain: "icloud.com" },
  { name: "Amazon", domain: "amazon.com" },
  { name: "AWS", domain: "aws.amazon.com" },
  { name: "Dropbox", domain: "dropbox.com" },
  { name: "Adobe", domain: "adobe.com" },
  { name: "DocuSign", domain: "docusign.com" },
  { name: "Zoom", domain: "zoom.us" },
  { name: "Slack", domain: "slack.com" },
  { name: "GitHub", domain: "github.com" },
  { name: "LinkedIn", domain: "linkedin.com" },

  // Social
  { name: "Facebook", domain: "facebook.com" },
  { name: "Instagram", domain: "instagram.com" },
  { name: "Twitter/X", domain: "x.com" },
  { name: "WhatsApp", domain: "whatsapp.com" },
  { name: "TikTok", domain: "tiktok.com" },
  { name: "Snapchat", domain: "snapchat.com" },

  // E-commerce / Shipping (common lure category)
  { name: "eBay", domain: "ebay.com" },
  { name: "Netflix", domain: "netflix.com" },
  { name: "Walmart", domain: "walmart.com" },
  { name: "FedEx", domain: "fedex.com" },
  { name: "UPS", domain: "ups.com" },
  { name: "USPS", domain: "usps.com" },
  { name: "DHL", domain: "dhl.com" },

  // Government / Utility (common in regional phishing kits)
  { name: "IRS", domain: "irs.gov" },
  { name: "GOV.UK", domain: "gov.uk" }
];

// Common "safe" second-level suffixes that legitimately vary by region,
// used to avoid false positives (e.g. amazon.co.uk, amazon.de).
const REGIONAL_TLD_VARIANTS = [
  "co.uk", "co.in", "com.au", "com.br", "com.mx", "de", "fr", "it", "es",
  "nl", "jp", "co.jp", "ca", "com.sg", "co.nz"
];

if (typeof module !== "undefined") {
  module.exports = { KNOWN_BRANDS, REGIONAL_TLD_VARIANTS };
}
