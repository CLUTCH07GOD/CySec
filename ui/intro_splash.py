"""
UI Component: High-Tech Glassmorphic App Intro & Splash Screen
--------------------------------------------------------------
Renders an animated intro splash overlay on initial application launch.
"""

import time
import streamlit as st

def render_intro_splash_if_needed():
    """Renders a sleek high-tech splash screen on initial session launch."""
    if st.session_state.get("intro_completed", False) or st.session_state.get("username", "guest") != "guest":
        st.session_state.intro_completed = True
        return

    st.session_state.intro_completed = True

    # Full screen splash overlay CSS & HTML with smooth auto fade-out
    st.markdown(
        """
        <style>
        .splash-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            width: 100vw; height: 100vh;
            background: radial-gradient(circle at 50% 40%, #0d1222 0%, #060913 60%, #02040a 100%);
            z-index: 999999;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            backdrop-filter: blur(25px);
            animation: splashFadeOut 1.4s ease-out 1.0s forwards;
            pointer-events: none;
        }

        @keyframes splashFadeOut {
            0% { opacity: 1; visibility: visible; }
            99% { opacity: 0; visibility: visible; }
            100% { opacity: 0; visibility: hidden; display: none; }
        }

        .splash-shield {
            font-size: 4.5rem;
            margin-bottom: 1.2rem;
            filter: drop-shadow(0 0 35px rgba(56, 189, 248, 0.8));
            animation: splashPulse 1.8s ease-in-out infinite;
        }

        @keyframes splashPulse {
            0%, 100% { transform: scale(1) translateY(0); filter: drop-shadow(0 0 30px rgba(56, 189, 248, 0.7)); }
            50% { transform: scale(1.08) translateY(-6px); filter: drop-shadow(0 0 45px rgba(192, 132, 252, 0.95)); }
        }

        .splash-title {
            font-family: 'Outfit', sans-serif;
            font-size: 2.6rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 0%, #38bdf8 40%, #818cf8 80%, #c084fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.03em;
            margin: 0 0 0.6rem;
            filter: drop-shadow(0 4px 15px rgba(56, 189, 248, 0.3));
        }

        .splash-subtitle {
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: #94a3b8;
            font-size: 1.05rem;
            max-width: 650px;
            margin: 0 auto 1.8rem;
            line-height: 1.6;
        }

        .splash-loader-bar {
            width: 280px;
            height: 5px;
            background: rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            overflow: hidden;
            position: relative;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.3);
        }

        .splash-loader-fill {
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc, #34d399);
            border-radius: 10px;
            animation: loaderFill 1.0s cubic-bezier(0.65, 0, 0.35, 1) forwards;
        }

        @keyframes loaderFill {
            0% { width: 0%; }
            100% { width: 100%; }
        }

        .splash-tagline {
            margin-top: 1rem;
            font-size: 0.82rem;
            font-family: 'Fira Code', monospace;
            color: #38bdf8;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        </style>

        <div class="splash-overlay">
            <div class="splash-shield">🛡️</div>
            <h1 class="splash-title">Cybersecurity Compliance Platform</h1>
            <p class="splash-subtitle">
                Autonomous Multi-Agent Audit, Controls Cross-Mapping & Regulatory Intelligence Engine
            </p>
            <div class="splash-loader-bar">
                <div class="splash-loader-fill"></div>
            </div>
            <div class="splash-tagline">SYSTEM INITIALIZING</div>
        </div>
        """,
        unsafe_allow_html=True
    )
