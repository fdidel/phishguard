from phishguard.url_validation import validate_url

urls = [
    "https://www.google.com/search?q=test",
    "http://paypa1-secure-login-verify.example/account/update?id=3",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://example.com/login",
]

for url in urls:
    v = validate_url(url)
    print(url, "=>", v.hostname, "| reg:", v.registrable_domain, "| sub:", v.subdomain)
