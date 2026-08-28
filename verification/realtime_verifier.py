"""
Verification Module: Real-Time Ground Truth Interceptor
------------------------------------------------------
Invokes external cloud API (Nemotron/Gemini) or local offline CyberSec-Assistant-3B model
for real-time verification and auto-correction of LLM outputs against statutory ground truth.
"""

import streamlit as st

def run_realtime_verification(query: str, response_text: str, res_box, target_length: str = None) -> tuple[str, str]:
    """
    Runs real-time factual verification on the LLM response.
    Supports both OpenRouter/Gemini API and local AYI-NEDJIMI/CyberSec-Assistant-3B model.
    Returns a tuple of (updated_response_text, verification_badge_label).
    """
    verification_badge = "⚙️ Verification: Disabled"
    if st.session_state.get("enable_realtime_verifier", True):
        verifier_engine = st.session_state.get("verifier_engine_select", "Cloud API (OpenRouter / Nemotron)")
        length_preset = target_length or st.session_state.get("length_preset_radio", "Medium")
        
        status_label = "🔍 **Verifying answer accuracy against statutory ground truth...**"
        if "CyberSec" in verifier_engine:
            status_label = f"🛡️ **Auditing response with local CyberSec-Assistant-3B model ({length_preset} Mode)...**"

        with st.status(status_label, expanded=False) as v_status:
            try:
                if "CyberSec" in verifier_engine:
                    import verification.local_cybersec_verifier as local_v
                    eval_res = local_v.verify_and_heal_local(query, response_text, target_length=length_preset)
                    provider_tag = "CyberSec-Assistant-3B"
                else:
                    import gemini_verifier
                    eval_res = gemini_verifier.verify_and_heal_realtime(query, response_text)
                    provider_tag = eval_res.get("provider", "Nemotron 3 Ultra")

                if eval_res.get("is_healed"):
                    healed_text = eval_res.get("healed_answer", "")
                    response_text = healed_text
                    res_box.markdown(response_text)
                    v_status.update(label=f"✨ **Hallucination Auto-Corrected via {provider_tag}!**", state="complete", expanded=False)
                    st.toast(f"⚡ Real-time Interceptor auto-corrected claims via {provider_tag}!", icon="✨")
                    verification_badge = f"🛡️ Real-Time Verification: Auto-Corrected ({provider_tag})"
                else:
                    v_status.update(label=f"✅ **Verified Factual by {provider_tag}**", state="complete", expanded=False)
                    verification_badge = f"🛡️ Real-Time Verification: Verified Factual ({provider_tag})"
            except Exception as err:
                v_status.update(label=f"⚠️ Verification Note: {err}", state="error", expanded=False)
                verification_badge = "🛡️ Real-Time Verification: Evaluated"

    return response_text, verification_badge
