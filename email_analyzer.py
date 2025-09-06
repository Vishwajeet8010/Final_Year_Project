import yaml
import re
from email.parser import BytesParser
from email import policy
import argparse
from datetime import datetime, timedelta
import whois

# 1. Load YAML rules
def load_rules(rule_file):
    with open(rule_file, 'r') as f:
        return yaml.safe_load(f)

# 2. Parse .eml file
def parse_email(email_path):
    with open("emails/sample.eml", 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    body = msg.get_body(preferencelist=('plain', 'html'))
    body_text = body.get_content() if body else ""
    
    return {
        'subject': msg['subject'],
        'from': msg['from'],
        'body': body_text,
        'links': re.findall(r'http[s]?://[^\s"\']+', body_text),
        'attachments': [
            part.get_filename() 
            for part in msg.iter_attachments() 
            if part.get_filename()
        ]
    }

# 3. Check if a domain is newly registered (<30 days old)
def is_new_domain(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date) < timedelta(days=30)
    except:
        return False

# 4. Apply rules to email
def analyze_email(email_data, rules):
    results = []
    
    for rule in rules:
        if rule.get('keywords'):
            # Keyword-based rule (e.g., "urgent", "password")
            matches = sum(
                1 for keyword in rule['keywords'] 
                if keyword.lower() in email_data['body'].lower()
            )
            if matches >= rule.get('match_threshold', 1):
                results.append({
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'details': f"Matched keywords: {rule['keywords']}"
                })
        
        elif rule.get('condition') == 'http://':
            # Insecure link rule
            insecure_links = [
                link for link in email_data['links'] 
                if link.startswith('http://')
            ]
            if insecure_links:
                results.append({
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'details': f"Insecure links: {insecure_links}"
                })
        
        elif rule.get('check_domain_age'):
            # New domain rule
            suspicious_domains = []
            for link in email_data['links']:
                domain = re.search(r'https?://([^/]+)', link).group(1)
                if is_new_domain(domain):
                    suspicious_domains.append(domain)
            
            if suspicious_domains:
                results.append({
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'details': f"Newly registered domains: {suspicious_domains}"
                })
    
    return results

# 5. Main CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze emails for phishing/spam.')
    parser.add_argument('email_path', help='Path to the .eml file')
    args = parser.parse_args()

    rules = load_rules('rules/phishing_rules.yaml')
    email_data = parse_email(args.email_path)
    analysis_results = analyze_email(email_data, rules)

    print(f"\nAnalysis for: {args.email_path}")
    print("=" * 50)
    print(f"From: {email_data['from']}")
    print(f"Subject: {email_data['subject']}")
    
    if analysis_results:
        print("\n⚠️ Threats Detected:")
        for result in analysis_results:
            print(f"- [{result['severity'].upper()}] {result['rule']}: {result['details']}")
    else:
        print("\n✅ No threats detected.")