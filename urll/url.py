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
                'severity': 'High',
                'icon': 'code',
                'patterns': ['<script>', 'javascript:', 'onerror=', 'onload=']
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
                'name': 'Directory Traversal',
                'description': 'A vulnerability that allows attackers to access files outside the web root.',
                'severity': 'High',
                'icon': 'folder',
                'patterns': ['../', '..\\', '%2e%2e%2f', '%2e%2e\\']
            },
            {
                'name': 'Command Injection',
                'description': 'Checks for command injection patterns in user input.',
                'severity': 'Critical',
                'icon': 'terminal',
                'patterns': [';', '&&', '|', '`','$(', '${']
            },
            {
                'name': 'Open Redirect',
                'description': 'A vulnerability that allows attackers to redirect users to malicious sites.',
                'severity': 'Medium',
                'icon': 'redirect',
                'patterns': ['?redirect=', '?url=', '?next=','return=']
            },
            
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
            time.sleep(0.3)  
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
    