"""Hand-curated data behind the heuristics: lookalike characters, brands,
abuse-prone TLDs, shorteners and scam keywords."""

# Unicode characters that render like ASCII letters/digits, used for
# lookalike detection (paypa1.com, Cyrillic а in pаypal.com).
HOMOGLYPHS = {
    "а": "a",  # Cyrillic
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ԁ": "d",
    "ɡ": "g",  # Latin script small capital
    "ν": "v",  # Greek
    "ο": "o",
    "α": "a",
    "ρ": "p",
    "τ": "t",
    "1": "l",
    "0": "o",
    "5": "s",
    "3": "e",
    "4": "a",
    "8": "b",
    "9": "g",
    "7": "t",
    "2": "z",
    "€": "e",
    "£": "l",
}

# Brands these checks look for. The India list exists because regional
# fintech/phishing is badly covered by Western-only brand lists.
GLOBAL_BRANDS = [
    "paypal", "google", "microsoft", "apple", "icloud", "amazon",
    "facebook", "instagram", "whatsapp", "netflix", "linkedin",
    "twitter", "xbox", "steam", "dropbox", "office365", "outlook",
    "dhl", "fedex", "ups", "usps", "royalmail",
    "chase", "wellsfargo", "citibank", "hsbc", "barclays",
    "coinbase", "binance", "metamask", "ledger", "blockchain",
]

INDIA_BRANDS = [
    "paytm", "phonepe", "googlepay", "gpay", "bhimupi", "upi",
    "hdfcbank", "icicibank", "sbi", "statebankofindia", "axisbank",
    "kotak", "kotakbank", "yesbank", "pnb", "unionbankofindia",
    "aadhaar", "uidai", "pancard", "incometax", "gstportal",
    "irctc", "flipkart", "snapdeal", "myntra", "zomato", "swiggy",
    "byju", "vedantu", "cred", "jupiter", "fampay", "sliceit",
]

BRANDS = GLOBAL_BRANDS + INDIA_BRANDS

# Free/cheap registries that turn up constantly in phishing feeds.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",          # Freenom
    "xyz", "top", "club", "online", "site", "buzz", "icu", "cyou",
    "ru", "su", "cn", "cc", "ws", "info", "biz", "live", "rest",
    "monster", "quest", "lol", "sbs", "cam", "bar", "kim",
}

# Two-part suffixes the registered-domain approximation needs to split right.
MULTIPART_TLDS = {
    "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "res.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.za", "com.br", "co.jp", "com.tr", "com.cn",
}

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
    "tiny.cc", "bit.do", "adf.ly", "bl.ink", "s.id",
]

# Credential-harvest / scareware / fake-reward phrasing.
SUSPICIOUS_KEYWORDS = [
    "login-verify", "verify-account", "account-verify", "secure-login",
    "signin-secure", "update-password", "password-reset", "reset-pass",
    "unlock-account", "confirm-identity", "validate-session",
    "webmail-reset", "mailbox-upgrade", "mail-confirmation",
    "free-recharge", "cashback-claim", "wallet-kyc", "kyc-update",
    "kyc-expired", "reward-claim", "lottery-win", "prize-claim",
    "refund-claim", "cash-app", "earn-money", "get-rich",
    "account-suspended", "account-blocked", "urgent-action",
    "security-alert", "unusual-activity", "limited-time",
    "tax-refund", "covid-relief", "government-scheme",
    "apk-download", "mod-apk", "premium-free", "cracked",
]

EXECUTABLE_EXTENSIONS = [
    ".exe", ".msi", ".apk", ".bat", ".cmd", ".scr", ".ps1",
    ".jar", ".vbs", ".com", ".hta", ".dll", ".sh",
]
