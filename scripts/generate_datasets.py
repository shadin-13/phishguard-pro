"""
Generate large realistic datasets for PhishGuard Pro
- Phishing / Legitimate URLs (10,000+ samples)
- Spam / Ham emails (5,000+ samples)
"""
import csv
import random
import os
import hashlib

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ==================== URL DATASET ====================

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "bbc.com",
    "nytimes.com", "cnn.com", "ebay.com", "paypal.com", "adobe.com",
    "dropbox.com", "spotify.com", "zoom.us", "slack.com", "notion.so",
    "medium.com", "quora.com", "tripadvisor.com", "booking.com", "airbnb.com",
    "uber.com", "lyft.com", "walmart.com", "target.com", "bestbuy.com",
    "nike.com", "adidas.com", "samsung.com", "sony.com", "intel.com",
    "oracle.com", "ibm.com", "cisco.com", "vmware.com", "salesforce.com",
    "shopify.com", "wordpress.com", "blogger.com", "tumblr.com", "pinterest.com",
    "twitch.tv", "discord.com", "telegram.org", "whatsapp.com", "signal.org",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", "digitalocean.com",
    "heroku.com", "vercel.com", "netlify.com", "gitlab.com", "bitbucket.org",
    "mozilla.org", "w3.org", "ieee.org", "acm.org", "nature.com",
    "sciencedirect.com", "springer.com", "arxiv.org", "researchgate.net",
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "duolingo.com",
    "weather.com", "accuweather.com", "maps.google.com", "translate.google.com",
    "drive.google.com", "docs.google.com", "sheets.google.com", "calendar.google.com",
    "outlook.com", "office.com", "teams.microsoft.com", "onedrive.com",
    "icloud.com", "me.com", "yahoo.com", "aol.com", "protonmail.com",
    "gmail.com", "mail.google.com", "hotmail.com", "live.com", "msn.com"
]

LEGIT_PATHS = [
    "", "/", "/home", "/about", "/contact", "/products", "/services", "/blog",
    "/news", "/help", "/support", "/faq", "/login", "/signup", "/account",
    "/profile", "/settings", "/search", "/category/electronics", "/item/12345",
    "/docs/getting-started", "/api/v1/users", "/en-us/index.html", "/2024/article",
    "/user/johndoe", "/repo/project-name", "/watch?v=abc123", "/playlist"
]

PHISH_KEYWORDS = [
    "secure", "login", "signin", "verify", "update", "confirm", "account",
    "banking", "paypal", "appleid", "microsoft", "amazon", "ebay", "netflix",
    "wallet", "crypto", "bonus", "free", "prize", "urgent", "suspend",
    "limited", "alert", "security", "password", "unlock", "restore"
]

PHISH_TLDS = [".xyz", ".top", ".club", ".online", ".site", ".info", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc"]
PHISH_SUFFIXES = ["-secure", "-login", "-verify", "-update", "-account", "-support", "-alert", "secure-", "login-"]

def random_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = random.choice(["https", "https", "https", "http"])  # mostly https
    if random.random() < 0.3 and path:
        path += f"?id={random.randint(1,9999)}&ref=home"
    return f"{scheme}://www.{domain}{path}" if random.random() < 0.6 else f"{scheme}://{domain}{path}"

def random_phish_url():
    style = random.randint(0, 5)
    if style == 0:  # brand-lookalike
        brand = random.choice(["paypal", "apple", "microsoft", "amazon", "google", "facebook", "netflix", "ebay", "bankofamerica", "chase"])
        suffix = random.choice(PHISH_SUFFIXES)
        tld = random.choice(PHISH_TLDS)
        return f"http://{brand}{suffix}{random.choice(['', str(random.randint(1,99))])}{tld}/login"
    elif style == 1:  # IP based
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return f"http://{ip}/admin/login.php"
    elif style == 2:  # long suspicious
        kw = "-".join(random.sample(PHISH_KEYWORDS, 3))
        return f"http://{kw}{random.choice(PHISH_TLDS)}/verify?user=admin&token={random.randint(10000,99999)}"
    elif style == 3:  # subdomain trick
        brand = random.choice(["paypal", "apple", "amazon", "microsoft"])
        return f"http://{brand}.secure-login{random.choice(PHISH_TLDS)}/signin"
    elif style == 4:  # shortener-like
        return f"http://bit.ly/{hashlib.md5(str(random.random()).encode()).hexdigest()[:7]}"
    else:
        return f"http://login-{random.choice(PHISH_KEYWORDS)}{random.choice(PHISH_TLDS)}/account/update"

def generate_url_dataset(n_legit=15000, n_phish=15000):
    rows = []
    for _ in range(n_legit):
        rows.append({"url": random_legit_url(), "label": 0})
    for _ in range(n_phish):
        rows.append({"url": random_phish_url(), "label": 1})
    random.shuffle(rows)
    path = os.path.join(DATA_DIR, "phishing_urls.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Generated {len(rows)} URL samples → {path}")
    return path

# ==================== SPAM DATASET ====================

SPAM_TEMPLATES = [
    "Congratulations! You have won a free {item}. Click here to claim now: {url}",
    "Urgent: Your {brand} account will be suspended. Verify immediately: {url}",
    "Get rich quick! Make ${amount} per day working from home. Limited offer!",
    "You have been selected for a free {item}. Reply YES to claim your prize.",
    "Your package is waiting. Pay the shipping fee of ${amount} now or it will be returned.",
    "Hot singles in your area! Click to meet them tonight: {url}",
    "Claim your free Bitcoin now! Double your money instantly at {url}",
    "Your bank account has been locked. Login here to unlock: {url}",
    "Win a free {item}! Just enter your credit card details at {url}",
    "Act now! Exclusive offer expires in 24 hours. Buy now at {url}",
    "Dear user, your {brand} account needs verification. Click: {url}",
    "You have unpaid tax of ${amount}. Pay immediately or face legal action.",
    "Free gift card of ${amount} waiting for you. Confirm your details now.",
    "Your {brand} subscription expired. Update payment method here: {url}",
    "Security alert: unusual login detected from {place}. Confirm it was you: {url}",
    "You are the lucky winner of our {item} giveaway! Claim at {url}",
    "Final warning: Your account will be deleted in 24 hours unless you verify: {url}",
    "Earn ${amount} weekly with no experience needed. Apply now!",
    "Your refund of ${amount} is ready. Provide bank details at {url}",
    "Limited time: Get 90% off on all products. Shop now {url}"
]

HAM_TEMPLATES = [
    "Hi {name}, can we schedule the meeting for tomorrow at {time}?",
    "Please find the attached report for last month's sales figures.",
    "Thank you for your email. I will get back to you by {day}.",
    "The project deadline has been extended to next {day}.",
    "Let's discuss the requirements in today's standup meeting.",
    "I have shared the Google Doc with the team. Please review.",
    "Happy birthday {name}! Hope you have a great day.",
    "The server maintenance is scheduled for this weekend from 2 AM.",
    "Please review the pull request when you have time. Thanks.",
    "Looking forward to our call at {time} today.",
    "The quarterly review meeting is confirmed for Monday at {time}.",
    "Here is the agenda for the upcoming workshop next week.",
    "Thanks for the update. Everything looks good on my end.",
    "Can you send me the latest version of the document?",
    "I will be on leave next week. Please cover my tasks if needed.",
    "The client approved the design mockups. We can proceed to development.",
    "Reminder: Team lunch is scheduled for Friday at 1 PM.",
    "I have updated the ticket with the latest status. Please check.",
    "Could you clarify the requirements for the payment module?",
    "Great work on the presentation yesterday. The stakeholders were impressed."
]

ITEMS = ["iPhone", "Laptop", "Gift Card", "Vacation", "Smart Watch", "Headphones", "Tablet"]
BRANDS = ["PayPal", "Netflix", "Amazon", "Apple", "Microsoft", "Google", "Bank"]
NAMES = ["John", "Sarah", "Mike", "Emily", "David", "Lisa", "Alex", "Priya", "Rahim"]
PLACES = ["Russia", "China", "Nigeria", "Unknown location", "New York"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["10 AM", "11 AM", "2 PM", "3 PM", "4:30 PM"]

def fill_spam(t):
    return t.format(
        item=random.choice(ITEMS),
        brand=random.choice(BRANDS),
        amount=random.choice([50, 100, 250, 500, 1000, 5000]),
        url="http://" + random.choice(["secure-login", "claim-now", "verify-account"]) + random.choice(PHISH_TLDS),
        place=random.choice(PLACES),
        name=random.choice(NAMES),
        day=random.choice(DAYS),
        time=random.choice(TIMES)
    )

def fill_ham(t):
    return t.format(
        name=random.choice(NAMES),
        day=random.choice(DAYS),
        time=random.choice(TIMES)
    )

def generate_spam_dataset(n_spam=8000, n_ham=8000):
    rows = []
    for _ in range(n_spam):
        rows.append({"text": fill_spam(random.choice(SPAM_TEMPLATES)), "label": 1})
    for _ in range(n_ham):
        rows.append({"text": fill_ham(random.choice(HAM_TEMPLATES)), "label": 0})
    # Add some variation
    for _ in range(500):
        rows.append({"text": "URGENT!!! " + fill_spam(random.choice(SPAM_TEMPLATES)).upper(), "label": 1})
    for _ in range(500):
        rows.append({"text": "Re: " + fill_ham(random.choice(HAM_TEMPLATES)), "label": 0})
    random.shuffle(rows)
    path = os.path.join(DATA_DIR, "spam_emails.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Generated {len(rows)} email samples → {path}")
    return path

if __name__ == "__main__":
    print("Generating datasets for PhishGuard Pro...")
    generate_url_dataset(6000, 6000)
    generate_spam_dataset(3000, 3000)
    print("Done!")
