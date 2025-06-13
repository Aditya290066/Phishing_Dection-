import pandas as pd
import re

def url_length(url):
    return len(url)

def has_at_symbol(url):
    return '@' in url

def has_ip_address(url):
    ip_pattern = r'http[s]?://(\d{1,3}\.){3}\d{1,3}'
    return re.search(ip_pattern, url) is not None

def count_dots(url):
    return url.count('.')

def has_suspicious_keywords(url):
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'webscr', 'signin']
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in keywords)

def uses_https(url):
    return url.startswith('https://')

def is_suspicious(url):
    score = 0
    if url_length(url) > 75:
        score += 1
    if has_at_symbol(url):
        score += 1
    if has_ip_address(url):
        score += 1
    if count_dots(url) > 3:
        score += 1
    if has_suspicious_keywords(url):
        score += 1
    if not uses_https(url):
        score += 1
    return score >= 3

def main():
    data = pd.read_csv('phishing_site_urls.csv')
    data['predicted'] = data['URL'].apply(is_suspicious)  # Changed 'url' to 'URL'
    data['label'] = data['Label'].apply(lambda x: True if x == 'bad' else False)  # Convert labels to boolean
    confusion = pd.crosstab(data['label'], data['predicted'], rownames=['Actual'], colnames=['Predicted'])
    print(confusion)
    accuracy = (data['label'] == data['predicted']).mean()
    print(f'Accuracy: {accuracy:.2%}')

if __name__ == "__main__":
    main()