import csv
import random


OUTPUT_FILE = "data/training_data.csv"
SAFE_COUNT = 10000
PHISHING_COUNT = 10000

random.seed(42)

SAFE_DOMAINS = [
    "google.com",
    "amazon.com",
    "microsoft.com",
    "github.com",
    "python.org",
    "wikipedia.org",
    "stackoverflow.com",
    "openai.com",
    "apple.com",
    "mozilla.org",
    "linkedin.com",
    "reddit.com",
    "nytimes.com",
    "bbc.com",
    "cnn.com",
    "coursera.org",
    "khanacademy.org",
    "mit.edu",
    "stanford.edu",
    "harvard.edu",
    "nasa.gov",
    "who.int",
    "un.org",
    "dropbox.com",
    "adobe.com",
    "salesforce.com",
    "cloudflare.com",
    "digitalocean.com",
    "ubuntu.com",
    "debian.org",
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "kubernetes.io",
    "gitlab.com",
    "bitbucket.org",
    "medium.com",
    "dev.to",
    "quora.com",
    "imdb.com"
]

SAFE_PATHS = [
    "",
    "/",
    "/about",
    "/contact",
    "/products",
    "/docs",
    "/help",
    "/login",
    "/support",
    "/blog",
    "/careers",
    "/privacy",
    "/terms",
    "/pricing",
    "/download",
    "/developer",
    "/api",
    "/news",
    "/learn",
    "/education",
    "/account",
    "/settings",
    "/profile",
    "/search",
    "/faq",
    "/community",
    "/events",
    "/status",
    "/security",
    "/updates",
    "/release-notes",
    "/customers",
    "/enterprise",
    "/solutions",
    "/resources"
]

PHISHING_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "bank",
    "wallet",
    "confirm",
    "billing",
    "signin",
    "sign-in",
    "auth",
    "authentication",
    "recover",
    "recovery",
    "unlock",
    "locked",
    "suspend",
    "suspended",
    "alert",
    "urgent",
    "security",
    "validate",
    "validation",
    "payment",
    "invoice",
    "refund",
    "claim",
    "bonus",
    "gift",
    "reward",
    "limited",
    "expired",
    "expire",
    "reset",
    "identity",
    "personal",
    "kyc",
    "document",
    "token",
    "otp",
    "2fa",
    "mfa"
]

FAKE_BRANDS = [
    "paypal",
    "google",
    "amazon",
    "microsoft",
    "apple",
    "netflix",
    "bank",
    "github",
    "facebook",
    "instagram",
    "whatsapp",
    "twitter",
    "x",
    "linkedin",
    "dropbox",
    "adobe",
    "steam",
    "spotify",
    "discord",
    "telegram",
    "binance",
    "coinbase",
    "wellsfargo",
    "chase",
    "bankofamerica",
    "hsbc",
    "icici",
    "hdfc",
    "sbi",
    "axisbank",
    "paytm",
    "phonepe",
    "googlepay",
    "upi",
    "irs",
    "gov",
    "tax",
    "fedex",
    "dhl",
    "ups",
    "usps"
]



def generate_safe_url():
    domain = random.choice(SAFE_DOMAINS)
    scheme = random.choice(["https", "https", "https", "http"])
    path = random.choice(SAFE_PATHS)
    return f"{scheme}://www.{domain}{path}"
def generate_phishing_url():
    word1 = random.choice(PHISHING_WORDS)
    word2 = random.choice(PHISHING_WORDS)
    brand = random.choice(FAKE_BRANDS)
    pattern = random.randint(1, 6)
    if pattern == 1:
        return f"http://{brand}-{word1}-{word2}.example/login"
    if pattern == 2:
        return f"http://192.168.{random.randint(0, 255)}.{random.randint(1, 254)}/{word1}-{word2}"
    if pattern == 3:
        # @ symbol trick
        return f"http://{brand}.com@evil-{word1}.example/{word2}"
    if pattern == 4:
        # Many subdomains
        return f"http://secure.login.{brand}.{word1}.{word2}.example/update"
    if pattern == 5:
        # Long suspicious path
        return f"https://{brand}-{word1}.example/{word1}/{word2}/account/update/password/confirm"
    # Many hyphens
    return f"http://{brand}-{word1}-{word2}-security-check.example"

def create_dataset():
    # Store rows as dictionaries
    rows = []
    # Generate safe examples
    for _ in range(SAFE_COUNT):
        rows.append({
            "url": generate_safe_url(),
            "label": 0
        })
    # Generate phishing examples
    for _ in range(PHISHING_COUNT):
        rows.append({
            "url": generate_phishing_url(),
            "label": 1
        })
    # Shuffle rows so safe and phishing URLs are mixed
    random.shuffle(rows)
    # Write dataset to CSV
    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)
    print("Dataset created:", OUTPUT_FILE)
    print("Total rows:", len(rows))
if __name__ == "__main__":
    create_dataset()
