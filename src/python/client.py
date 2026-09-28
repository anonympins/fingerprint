import copy
import json
import random
import uuid
from html import escape
from typing import Any, Dict, Optional


class FingerprintClient:
    """HTML templating and script tag injection utilities."""
    def __init__(self, client_script_path: str, client_config: Optional[Dict[str, Any]] = None):
        self.client_script_path = client_script_path
        default_config = {
            "mouse": True, "keystrokes": True, "clicks": True, "honeypots": [],
            "fetch": {"handleChallenges": True, "probationaryTtl": 30000},
            "wasm": True, "wasmPath": "/fp.js"
        }
        self.client_config = copy.deepcopy(default_config)
        if client_config:
            self.client_config.update(client_config)
        self.nonce = uuid.uuid4().hex[:16]

    def generate_honeypot_field(self, field_name: str) -> str:
        if field_name not in self.client_config["honeypots"]:
            self.client_config["honeypots"].append(field_name)
        style_options = [
            "position:absolute; left:-9999px; top:-9999px; transform:scale(0); opacity:0; pointer-events:none;",
            "position:fixed; left:-8888px; top:-8888px; width:0; height:0; overflow:hidden; opacity:0; pointer-events:none;",
            "display:none; visibility:hidden; pointer-events:none;"
        ]
        styles = random.choice(style_options)
        tag = random.choice(["div", "span", "p", "section"])
        f_name = escape(field_name)
        if random.randint(0, 1) == 1:
            return f'<{tag} style="{styles}" aria-hidden="true"><label for="{f_name}">{f_name}<input type="text" id="{f_name}" name="{f_name}" tabindex="-1" autocomplete="off"></label></{tag}>'
        return f'<{tag} style="{styles}" aria-hidden="true"><label for="{f_name}">{f_name}</label><input type="text" id="{f_name}" name="{f_name}" tabindex="-1" autocomplete="off"></{tag}>'

    def get_script_tag(self) -> str:
        config_json = json.dumps(self.client_config)
        nonce_attr = f' nonce="{self.nonce}"' if self.nonce else ""
        init_script = f"""
         document.addEventListener('DOMContentLoaded', function() {{
             const config = {config_json};
             if (window.ClientLibrary) {{
                 if (config.wasmPath) {{
                     const wasmScript = document.createElement('script');
                     wasmScript.src = config.wasmPath;
                     wasmScript.async = true;
                     wasmScript.nonce = '{self.nonce}';
                     document.head.appendChild(wasmScript);
                 }}
                 window.ClientLibrary.initializeClient(config);
             }} else {{
                 console.error('Fingerprint client library not loaded.');
             }}
         }});"""
        return f'<script src="{escape(self.client_script_path)}"{nonce_attr}></script><script{nonce_attr}>{init_script}</script>'