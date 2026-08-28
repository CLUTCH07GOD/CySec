"""
UI Component: Modern Authentication & Registration Portal
---------------------------------------------------------
Renders an enterprise glassmorphic portal supporting:
1. Standard Username/Password Authentication.
2. Email / Username Sign In via Application-Generated 6-Digit OTP.
3. Comprehensive Registration metadata collection (Full Name, Phone, Organization, Designation, Work Email).
4. Guest Access mode.
"""

import streamlit as st
import core.auth_manager as auth

def render_login_page():
    """Renders full-screen glassmorphic login & registration portal."""
    
    st.markdown(
        """
        <style>
        .login-hero-container {
            text-align: center;
            padding: 2rem 1rem 1.2rem;
            max-width: 680px;
            margin: 0 auto;
        }

        .login-brand-shield {
            font-size: 4rem;
            margin-bottom: 0.6rem;
            filter: drop-shadow(0 0 35px rgba(56, 189, 248, 0.75));
            animation: floatShield 4s ease-in-out infinite;
        }

        .login-brand-title {
            font-family: 'Outfit', sans-serif;
            font-size: 2.4rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 0%, #38bdf8 45%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
            margin: 0 0 0.4rem;
        }

        .login-brand-sub {
            color: #94a3b8;
            font-size: 1rem;
            line-height: 1.5;
            margin: 0;
        }

        .auth-card-wrapper {
            background: linear-gradient(145deg, rgba(13, 18, 34, 0.92) 0%, rgba(20, 27, 49, 0.85) 100%);
            backdrop-filter: blur(28px);
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 24px;
            padding: 2rem 2.2rem;
            box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.65), 0 0 30px rgba(56, 189, 248, 0.2);
            margin-top: 0.8rem;
        }

        .otp-box {
            background: rgba(14, 165, 233, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.4);
            border-radius: 12px;
            padding: 12px 16px;
            margin: 12px 0;
            text-align: center;
        }

        .guest-feature-box {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(148, 163, 184, 0.25);
            border-radius: 14px;
            padding: 16px;
            margin-bottom: 18px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="login-hero-container">
            <div class="login-brand-shield">🛡️</div>
            <h1 class="login-brand-title">Cybersecurity Compliance Platform</h1>
            <p class="login-brand-sub">Autonomous Multi-Agent Audit, Controls Cross-Mapping & Regulatory Intelligence</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns([1, 2.4, 1])

    with col2:
        st.markdown('<div class="auth-card-wrapper">', unsafe_allow_html=True)
        
        tab_login, tab_otp, tab_register, tab_guest = st.tabs([
            "**Password Sign In**", "**Email OTP Sign In**", "**Register Account**", "**Guest Portal**"
        ])

        # ---------------------------------------------------------------------
        # TAB 1: Password Sign In
        # ---------------------------------------------------------------------
        with tab_login:
            st.markdown("<p style='color: #94a3b8; font-size: 0.9rem; margin-top: 10px;'>Enter your username/email and password to log in.</p>", unsafe_allow_html=True)
            login_user = st.text_input("Username or Email", key="login_username_input")
            login_pass = st.text_input("Password", type="password", key="login_password_input")
            
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            if st.button("**Sign In with Password**", type="primary", width="stretch", key="login_submit_btn"):
                if not login_user or not login_pass:
                    st.error("Please enter both username/email and password.")
                else:
                    user_info = auth.authenticate_user(login_user, login_pass)
                    if user_info:
                        st.session_state.authenticated = True
                        st.session_state.username = user_info["username"]
                        st.session_state.user_role = user_info["role"]
                        st.session_state.intro_completed = True
                        st.toast(f"Welcome back, {user_info['username']}! ({user_info['role'].upper()})")
                        st.rerun()
                    else:
                        st.error("Invalid credentials. Please try again.")

        # ---------------------------------------------------------------------
        # TAB 2: Email / Username Sign In via Application Generated OTP
        # ---------------------------------------------------------------------
        with tab_otp:
            st.markdown("<p style='color: #94a3b8; font-size: 0.9rem; margin-top: 10px;'>Sign in without a password using an application-generated 6-digit OTP code.</p>", unsafe_allow_html=True)
            
            otp_identifier = st.text_input("Registered Email Address or Username", placeholder="auditor@company.com", key="login_otp_id_input")
            
            if st.session_state.get("active_otp_id") == otp_identifier and st.session_state.get("otp_requested"):
                st.markdown(
                    f"""
                    <div class="otp-box">
                        <span style="color: #38bdf8; font-size: 0.88rem; font-weight: 500;">
                            Verification OTP code sent to owner of <strong>{otp_identifier}</strong>. Please check your email inbox.
                        </span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                
                user_otp_code = st.text_input("Enter 6-Digit OTP Code", key="user_otp_input", placeholder="123456")
                
                col_o1, col_o2 = st.columns(2)
                with col_o1:
                    if st.button("**Verify OTP & Sign In**", type="primary", width="stretch", key="verify_otp_btn"):
                        ok, user_data, msg = auth.verify_email_otp(otp_identifier, user_otp_code)
                        if ok and user_data:
                            st.session_state.authenticated = True
                            st.session_state.username = user_data["username"]
                            st.session_state.user_role = user_data["role"]
                            st.session_state.intro_completed = True
                            st.session_state.pop("active_otp_id", None)
                            st.session_state.pop("otp_requested", None)
                            st.toast(f"OTP verified! Welcome back {user_data['username']}")
                            st.rerun()
                        else:
                            st.error(msg)
                with col_o2:
                    if st.button("Resend OTP", width="stretch", key="resend_otp_btn"):
                        ok, msg, _ = auth.generate_email_otp(otp_identifier)
                        if ok:
                            st.session_state["active_otp_id"] = otp_identifier
                            st.session_state["otp_requested"] = True
                            st.success("New verification OTP dispatched to registered email inbox.")
                        else:
                            st.error(msg)
            else:
                if st.button("**Send Verification OTP**", width="stretch", key="gen_otp_btn"):
                    ok, msg, _ = auth.generate_email_otp(otp_identifier)
                    if ok:
                        st.session_state["active_otp_id"] = otp_identifier
                        st.session_state["otp_requested"] = True
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

        # ---------------------------------------------------------------------
        # TAB 3: Comprehensive Registration Form
        # ---------------------------------------------------------------------
        with tab_register:
            st.markdown("<p style='color: #94a3b8; font-size: 0.88rem; margin-top: 6px;'>Create a complete corporate compliance profile for audit logging.</p>", unsafe_allow_html=True)
            
            reg_fullname = st.text_input("Full Name", key="reg_fullname_input")
            col_reg1, col_reg2 = st.columns(2)
            with col_reg1:
                reg_user = st.text_input("Username*", key="reg_username_input")
                reg_email = st.text_input("Work Email Address*", key="reg_email_input")
                reg_pass = st.text_input("Password*", type="password", key="reg_password_input")
            with col_reg2:
                reg_phone = st.text_input("Phone Number", key="reg_phone_input")
                reg_org = st.text_input("Organization / Company", key="reg_org_input")
                reg_pass_confirm = st.text_input("Confirm Password*", type="password", key="reg_pass_confirm_input")
                
            reg_designation = st.selectbox(
                "Compliance Role / Designation",
                options=[
                    "Chief Information Security Officer (CISO)",
                    "Compliance Auditor / Officer",
                    "Data Privacy Officer (DPO)",
                    "Security Engineer / Analyst",
                    "IT Systems Administrator",
                    "Legal Counsel / Regulatory Specialist",
                    "Executive / Manager",
                    "Other"
                ],
                key="reg_designation_select"
            )

            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
            if st.button("**Create Account & Register**", type="primary", width="stretch", key="reg_submit_btn"):
                if not reg_user or not reg_pass:
                    st.error("Username and Password are required.")
                elif reg_pass != reg_pass_confirm:
                    st.error("Passwords do not match.")
                else:
                    success, msg = auth.register_user(
                        username=reg_user,
                        password=reg_pass,
                        email=reg_email,
                        full_name=reg_fullname,
                        phone=reg_phone,
                        organization=reg_org,
                        designation=reg_designation,
                        role="registered",
                        auth_provider="local"
                    )
                    if success:
                        st.success("Account created successfully! Please switch to Password or Email OTP Sign In tab to log in.")
                    else:
                        st.error(msg)

        # ---------------------------------------------------------------------
        # TAB 4: Guest Portal
        # ---------------------------------------------------------------------
        with tab_guest:
            st.markdown(
                """
                <div class="guest-feature-box">
                    <h4 style="color: #38bdf8; margin-top: 0; margin-bottom: 8px; font-size: 1.05rem;">Guest Access Privileges</h4>
                    <ul style="color: #cbd5e1; font-size: 0.88rem; padding-left: 20px; margin-bottom: 0; line-height: 1.6;">
                        <li>Ask NIST, EU, and India framework compliance questions</li>
                        <li>Run 1-click audit shortcuts & export DOCX reports</li>
                        <li><strong>Session Limit:</strong> Up to 5 interactive queries</li>
                        <li>No persistent chat history saving</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            if st.button("**Continue as Guest**", width="stretch", key="guest_continue_btn"):
                st.session_state.authenticated = True
                st.session_state.username = "guest"
                st.session_state.user_role = "guest"
                st.session_state.intro_completed = True
                st.toast("Continuing in Guest Mode.")
                st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)
