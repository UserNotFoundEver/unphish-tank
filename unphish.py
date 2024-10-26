from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# List of suspicious keywords, domains, and TLDs. You may update this script with further encryption or attatch it to an API that alerts you of known urls that
# are currently unsafe / hacked, so it's more than just a security tool to check if a link is a phishing link with further development. We don't publish all for the sake of security itself of course.
# The "LIST", dictionary, pandas etc will and has expanded. This has basic level encryption.
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "update", "account", "user", "portal",
    "urgent", "alert", "support", "warning", "notice", "suspended", "apple", "paypal",
    "facebook", "amazon", "microsoft", "yahoo", "outlook", "gmail", "twitter", "instagram",
    "whatsapp", "invoice", "payment", "order", "confirm", "bank", "ebay", "netflix", 
    "urgent", "immediate", "locked", "recovery", "win", "free", "reward", "gift", 
    "bonus", "claim", "deal", "offer", "discount"
]
SUSPICIOUS_DOMAINS = [
    "paypal", "secure-", "appleid", "outlook", "microsoft", "account-", "login-",
    "signin-", "alert-", "verify-", "gmail", "myaccount", "tinyurl.com", "bit.ly",
    "goo.gl", "grabify.link", "iplogger", "secure-", "banking-", "web-", "ebanking",
    "twitter", "instagram", "amazon", "netflix", "linkedin", "snapchat", "adobe"
]
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".pw", ".click", ".support", 
    ".info", ".live", ".pro", ".tech", ".inc", ".me", ".cc", ".is", ".so", 
    ".ac", ".cx", ".sh", ".name", ".gg", ".mx", ".gdn", ".new", ".domains", 
    ".sucks", ".fyi", ".ai"
]

# Encryption settings
KEY = get_random_bytes(16)  # AES key for encryption
IV = get_random_bytes(16)   # Initialization vector

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(encrypted_data).decode()

def decrypt(encrypted_data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
    return decrypted_data.decode()

def analyze_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    
    is_suspicious = False
    reasons = []

    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            is_suspicious = True
            reasons.append(f"Contains suspicious keyword: '{keyword}'")
            break

    # Check for suspicious domains
    for domain in SUSPICIOUS_DOMAINS:
        if domain in hostname:
            is_suspicious = True
            reasons.append(f"Contains suspicious domain: '{domain}'")
            break

    # Check for suspicious TLDs
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        is_suspicious = True
        reasons.append(f"Contains suspicious TLD: '{hostname.split('.')[-1]}'")

    # Display and encrypt results
    if is_suspicious:
        result = f"\n[!] Warning: {url} may be suspicious.\n" + "\n".join([f"   - {reason}" for reason in reasons])
        encrypted_result = encrypt(result)
        print(f"\nEncrypted Result: {encrypted_result}")
    else:
        result = f"\n[+] {url} appears safe."
        encrypted_result = encrypt(result)
        print(f"\nEncrypted Result: {encrypted_result}")

    # Decrypt for testing purposes
    print("\nDecrypted for verification:", decrypt(encrypted_result))

# Example usage:
analyze_url("https://google.com")
