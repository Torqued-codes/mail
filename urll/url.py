from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import time  
a = Flask(__name__, static_folder='static')
CORS(a, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

class url:
    def __init__(self):  
        self.vulnerability_score = [  
            {
                'name': 'SQL Injection',
                'description': 'A code injection technique that might destroy your database.',
                'severity': 'High',
                'icon': 'database',
                'patterns': ["'", '"', 'OR 1=1', 'UNION SELECT']
            },
            {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'A vulnerability that allows attackers to inject malicious scripts.',
                'severity': 'Medium',
                'icon': 'script',
                'patterns': ['<script>', 'javascript:', 'onerror=', 'onload=']
            },
            {
                'name': 'Remote Code Execution (RCE)',
                'description': 'A vulnerability that allows an attacker to execute arbitrary code.',
                'severity': 'Critical',
                'icon': 'code',
                'patterns': [';', '&&', '|', '`']
            },
            {
                'name': 'Directory Traversal',
                'description': 'A vulnerability that allows attackers to access files outside the web root.',
                'severity': 'High',
                'icon': 'folder',
                'patterns': ['../', '..\\', '%2e%2e%2f', '%2e%2e\\']
            },
            {
                'name': 'Insecure Direct Object References (IDOR)',
                'description': 'A vulnerability that exposes internal implementation objects.',
                'severity': 'High',
                'icon': 'key',
                'patterns': ['/file?id=', '/user?id=', '/document?id=']
            },
            {
                'name': 'Cross-Site Request Forgery (CSRF)',
                'description': 'A vulnerability that tricks a user into submitting a malicious request.',
                'severity': 'Medium',
                'icon': 'shield',
                'patterns': ['<form', '<input type="hidden"', '<button type="submit"']
            },
            {
                'name': 'Open Redirect',
                'description': 'A vulnerability that allows attackers to redirect users to malicious sites.',
                'severity': 'Medium',
                'icon': 'redirect',
                'patterns': ['?redirect=', '?url=', '?next=']
            },
            {
                'name': 'File Inclusion',
                'description': 'A vulnerability that allows an attacker to include a file via a script.',
                'severity': 'High',
                'icon': 'file',
                'patterns': ['?include=', '?file=', '?page=']
            },
            {
                'name': 'Command Injection',
                'description': 'Checks for command injection patterns in user input.',
                'severity': 'Critical',
                'icon': 'terminal',
                'patterns': [';', '&&', '|', '`']
            },
            {
                'name': 'HTTPS/SSL Check',  
                'description': 'Checks if the URL uses HTTPS and has a valid SSL certificate.',
                'severity': 'Medium',
                'icon': 'lock',
                'patterns': [],  
                'custom_check': "lambda url: not url.startswith('https://')"  
            },
            {
                'name': 'URL Shortener Detection',
                'description': 'Detects if the URL is using a known URL shortening service.',
                'severity': 'Medium',
                'icon': 'link',
                'patterns': ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
                             'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly']
            }
        ]

    def test_vulnerabilities(self, url, test):
        if test.get('custom_check'):
            if eval(test['custom_check'])(url):
                return True
            return False  

        patterns = test.get('patterns', [])
        url_lower = url.lower()

        for pattern in patterns:
            if pattern in url_lower:
                return True
        return False

    def scan_url(self, url):
        results = []
        for test in self.vulnerability_score:
            time.sleep(0.5)  
            vulnerable = self.test_vulnerabilities(url, test)
            results.append({
                'name': test['name'],
                'description': test['description'],
                'severity': test['severity'],
                'icon': test['icon'],
                'vulnerable': vulnerable
            })

        return results


scanner = url()

@a.route('/')
def home():
    return send_from_directory('static', 'index.html')

@a.route('/scan', methods=['POST'])
def index():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        results = scanner.scan_url(url)
        vulnerable_count = sum(1 for r in results if r['vulnerable'])
        safe_count = len(results) - vulnerable_count

        return jsonify({
            'success': True,
            'results': results,
            'stats': {
                'total_tests': len(results),
                'vulnerable': vulnerable_count,
                'safe_count': safe_count
            }
        })
    except Exception as e:
        return jsonify({'error': 'An error occurred during scanning', 'details': str(e)}), 500


if __name__ == '__main__':
    a.run(debug=True, port=5000)