import re

def analyze_email(sender, subject, body):
    score = 0
    reasons = []

    suspicious_domains = [
        'paypa1.com', 'amaz0n.com', 'g00gle.com', 'micros0ft.com','rnicrosoft.com',
        'apple-support.com', 'secure-login.com', 'nvclia.com','openaii.com','account-verify.com'
    ]
    if any(domain in sender.lower() for domain in suspicious_domains):
        score += 40
        reasons.append("⚠️  Suspicious sender domain detected")

    free_providers = ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com']
    official_keywords = ['bank', 'paypal', 'amazon', 'apple', 'microsoft', 'netflix']
    if any(p in sender.lower() for p in free_providers):
        if any(k in sender.lower() or k in subject.lower() for k in official_keywords):
            score += 30
            reasons.append("⚠️  Official service using a free email provider")

    urgent_words = [
        'urgent', 'act now', 'immediately', 'suspended', 'verify now',''
        'account locked', 'limited time', 'final warning', 'click here',
        'confirm your identity', 'unusual activity'
    ]
    found_urgent = [w for w in urgent_words if w in body.lower() or w in subject.lower()]
    if found_urgent:
        score += 20
        reasons.append(f"⚠️  Urgent/threatening language found: {', '.join(found_urgent)}")

    if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', body):
        score += 30
        reasons.append("⚠️  IP address used as a link (very suspicious)")

    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'rb.gy']
    if any(s in body.lower() for s in shorteners):
        score += 20
        reasons.append("⚠️  URL shortener detected in email body")

    if 'http://' in body.lower():
        score += 10
        reasons.append("⚠️  Non-secure HTTP link found")

    sensitive_keywords = [
        'password', 'credit card', 'social security', 'ssn','account number','cvv','security code','login credentials','personal information','sensitive data','financial information','account details','social security number','credit card number','expiration date','security code','login info','account credentials','personal info','sensitive info','confidential data','private information','bank details',
        'bank account', 'otp', 'pin', 'date of birth','mother\'s maiden name', 'passport number', 'driver\'s license','security question','two-factor authentication','2fa code','verification code','access code','secret question','recovery email','backup codes', 'security answer', 'account recovery', 'identity verification','personal details','confidential information','private key','secret key','api key','encryption key','decryption key','security token','auth token','session token',
    ]
    found_sensitive = [k for k in sensitive_keywords if k in body.lower()]
    if found_sensitive:
        score += 30
        reasons.append(f"⚠️  Requesting sensitive info: {', '.join(found_sensitive)}")

    if '<' in sender and '>' in sender:
        display_name = sender[:sender.index('<')].strip().lower()
        email_domain = sender[sender.index('<'):].lower()
        if display_name and not any(word in email_domain for word in display_name.split()):
            score += 20
            reasons.append("⚠️  Sender display name doesn't match email domain")

    grammar_red_flags = [
        'dear customer', 'dear user', 'valued member','dear sir/madam', 'greetings', 'hello friend','attention',
        'kindly revert', 'do the needful','apply now', 'click the link below', 'asap', 'immediately', 'urgent action required','verify your account', 'update your information','suspicious activity detected', 'account suspended', 'final notice', 'limited time offer', 'act now', 'last chance', 'exclusive deal', 'congratulations you won', 'free gift', 'risk-free', 'no obligation',
        'this is not a scam', '100% legit', 'guaranteed', 'once in a lifetime', 'you have been selected', 'winner', 'claim your prize', 'click here to claim', 'verify your identity', 'confirm your account', 'reset your password','unusual activity detected','account locked','security alert','important notice','update your account','verify your email','suspicious login attempt',
        'account verification required', 'urgent', 'immediately', 'act now', 'limited time', 'final warning', 'click here', 'confirm your identity', 'unusual activity', 'account locked', 'suspended', 'verify now', 'account suspended', 'final notice', 'limited time offer', 'act now', 'last chance', 'exclusive deal', 'congratulations you won', 'free gift', 'risk-free', 'no obligation','account verification required',
    ]
    if any(g in body.lower() for g in grammar_red_flags):
        score += 10
        reasons.append("⚠️  Generic/suspicious greeting or phrasing detected")

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