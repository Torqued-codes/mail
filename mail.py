import re

def analyze_email(sender, subject, body):
    score = 0
    reasons = []

    # ─── 1. Suspicious Sender Domain ───────────────────────────
    suspicious_domains = [
        'paypa1.com', 'amaz0n.com', 'g00gle.com', 'micros0ft.com',
        'apple-support.com', 'secure-login.com', 'account-verify.com'
    ]
    if any(domain in sender.lower() for domain in suspicious_domains):
        score += 40
        reasons.append("⚠️  Suspicious sender domain detected")

    # ─── 2. Generic/Free Email Provider for Official Mail ───────
    free_providers = ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com']
    official_keywords = ['bank', 'paypal', 'amazon', 'apple', 'microsoft', 'netflix']
    if any(p in sender.lower() for p in free_providers):
        if any(k in sender.lower() or k in subject.lower() for k in official_keywords):
            score += 30
            reasons.append("⚠️  Official service using a free email provider")

    # ─── 3. Urgent / Threatening Language ───────────────────────
    urgent_words = [
        'urgent', 'act now', 'immediately', 'suspended', 'verify now',
        'account locked', 'limited time', 'final warning', 'click here',
        'confirm your identity', 'unusual activity'
    ]
    found_urgent = [w for w in urgent_words if w in body.lower() or w in subject.lower()]
    if found_urgent:
        score += 20
        reasons.append(f"⚠️  Urgent/threatening language found: {', '.join(found_urgent)}")

    # ─── 4. Suspicious Links ────────────────────────────────────
    # IP address used as URL
    if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', body):
        score += 30
        reasons.append("⚠️  IP address used as a link (very suspicious)")

    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'rb.gy']
    if any(s in body.lower() for s in shorteners):
        score += 20
        reasons.append("⚠️  URL shortener detected in email body")

    # HTTP (not HTTPS) links
    if 'http://' in body.lower():
        score += 10
        reasons.append("⚠️  Non-secure HTTP link found")

    # ─── 5. Requests for Sensitive Info ─────────────────────────
    sensitive_keywords = [
        'password', 'credit card', 'social security', 'ssn',
        'bank account', 'otp', 'pin', 'date of birth'
    ]
    found_sensitive = [k for k in sensitive_keywords if k in body.lower()]
    if found_sensitive:
        score += 30
        reasons.append(f"⚠️  Requesting sensitive info: {', '.join(found_sensitive)}")

    # ─── 6. Mismatched Sender Name ──────────────────────────────
    if '<' in sender and '>' in sender:
        display_name = sender[:sender.index('<')].strip().lower()
        email_domain = sender[sender.index('<'):].lower()
        if display_name and not any(word in email_domain for word in display_name.split()):
            score += 20
            reasons.append("⚠️  Sender display name doesn't match email domain")

    # ─── 7. Poor Grammar / Spelling Indicators ──────────────────
    grammar_red_flags = [
        'dear customer', 'dear user', 'valued member',
        'kindly revert', 'do the needful'
    ]
    if any(g in body.lower() for g in grammar_red_flags):
        score += 10
        reasons.append("⚠️  Generic/suspicious greeting or phrasing detected")

    # ─── Result ─────────────────────────────────────────────────
    if score >= 60:
        verdict = "🚨 HIGH RISK — Very likely a phishing email!"
    elif score >= 30:
        verdict = "⚠️  MEDIUM RISK — Suspicious, proceed with caution."
    else:
        verdict = "✅ LOW RISK — Looks safe, but always stay cautious."

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons
    }

def main():
    print("=" * 50)
    print("       📧 Phishing Email Detector")
    print("=" * 50)

    sender  = input("\nEnter sender's email address: ").strip()
    subject = input("Enter email subject       : ").strip()
    body = input("Enter email body: ").strip()

    result = analyze_email(sender, subject, body)

    print("\n" + "=" * 50)
    print("              📊 ANALYSIS RESULT")
    print("=" * 50)
    print(f"\n🎯 Verdict     : {result['verdict']}")
    print(f"📈 Risk Score  : {result['risk_score']} / 100+")
    print(f"\n🔍 Reasons:")
    if result["reasons"]:
        for r in result["reasons"]:
            print(f"   {r}")
    else:
        print("   ✅ No red flags detected.")
    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()