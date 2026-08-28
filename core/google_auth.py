"""
Core Module: Google OAuth 2.0 & Identity Services Integration
--------------------------------------------------------------
Provides Google Identity Services (GIS) authentication, ID token verification,
and Google OAuth 2.0 authorization flows for Streamlit applications.
"""

import os
import json
import base64
import urllib.parse
from typing import Optional, Dict, Any
import streamlit as st

# Google Client ID from environment or secrets, fallback to demo client ID
GOOGLE_CLIENT_ID = os.environ.get(
    "GOOGLE_CLIENT_ID",
    st.secrets.get("GOOGLE_CLIENT_ID", "demo-google-client-id.apps.googleusercontent.com")
)

def decode_jwt_payload_unverified(id_token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes the JWT payload without signature verification for client-side tokens.
    In production with google-auth library, verify signature against Google's public keys.
    """
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Pad base64 string if necessary
        remainder = len(payload_b64) % 4
        if remainder:
            payload_b64 += "=" * (4 - remainder)
        decoded_bytes = base64.b64decode(payload_b64)
        return json.loads(decoded_bytes.decode("utf-8"))
    except Exception:
        return None

def render_google_identity_button(key_suffix: str = "main") -> None:
    """
    Renders Google Identity Services (GIS) HTML button and One-Tap prompt.
    Uses Google's official accounts.google.com/gsi/client library.
    """
    client_id = GOOGLE_CLIENT_ID
    
    # HTML component with Google Identity Services JS
    gis_html = f"""
    <div id="g_id_onload"
         data-client_id="{client_id}"
         data-context="signin"
         data-ux_mode="popup"
         data-callback="handleCredentialResponse"
         data-auto_prompt="false">
    </div>

    <div class="g_id_signin"
         data-type="standard"
         data-shape="rectangular"
         data-theme="filled_blue"
         data-text="signin_with"
         data-size="large"
         data-logo_alignment="left"
         data-width="100%">
    </div>

    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <script>
    function handleCredentialResponse(response) {{
        if (response.credential) {{
            // Post credential back to parent Streamlit frame
            window.parent.postMessage({{
                type: 'streamlit:setComponentValue',
                value: response.credential
            }}, '*');
        }}
    }}
    </script>
    """
    st.components.v1.html(gis_html, height=45)

def get_google_auth_redirect_url(redirect_uri: str = "http://localhost:8501") -> str:
    """Generates standard Google OAuth 2.0 authorization URL for browser redirect."""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "id_token token",
        "scope": "openid email profile",
        "nonce": "compliance_app_nonce",
        "prompt": "select_account"
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
