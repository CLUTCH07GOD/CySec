import streamlit as st
import core.auth_manager as auth

def render_header_and_metrics(available_fw_count: int, device_str: str, neo4j_active: bool, user_role: str = "guest", username: str = "guest"):
    """Renders Google Account-style sleek circular avatar with profile dropdown modal."""
    
    is_guest = not username or username == "guest" or user_role == "guest"
    user_prof = auth.get_user_profile(username) if not is_guest else None
    
    # User Profile Details
    full_name = (user_prof.get("full_name") if user_prof and user_prof.get("full_name") else username) if not is_guest else "Guest"
    display_greeting = full_name.split()[0].capitalize()
    user_email = user_prof.get("email", "") if user_prof else ""
    user_pic = user_prof.get("picture", "") if user_prof else ""
    initial = (full_name or username or "G")[0].upper()
    
    # Scoped CSS injection: strictly applies only to the top-right header avatar slot
    st.markdown(
        """
        <style>
        /* Beautified Top-Right Floating Circular Avatar Button ONLY */
        .header-avatar-slot div[data-testid="stPopover"] {
            display: flex !important;
            justify-content: flex-end !important;
            width: auto !important;
            float: right !important;
        }

        .header-avatar-slot div[data-testid="stPopover"] > button {
            width: 44px !important;
            height: 44px !important;
            min-width: 44px !important;
            max-width: 44px !important;
            border-radius: 50% !important;
            padding: 0 !important;
            margin: 0 !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            font-family: 'Outfit', sans-serif !important;
            font-weight: 800 !important;
            font-size: 1.25rem !important;
            color: #ffffff !important;
            background: linear-gradient(135deg, #2563eb 0%, #4f46e5 50%, #7c3aed 100%) !important;
            border: 2px solid #38bdf8 !important;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4), 0 0 15px rgba(56, 189, 248, 0.4) !important;
            cursor: pointer !important;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
            outline: none !important;
        }

        .header-avatar-slot div[data-testid="stPopover"] > button:hover {
            transform: scale(1.08) !important;
            box-shadow: 0 6px 22px rgba(56, 189, 248, 0.65) !important;
            border-color: #ffffff !important;
        }

        /* Remove default Streamlit dropdown arrows/chevrons inside circular avatar */
        .header-avatar-slot div[data-testid="stPopover"] button svg,
        .header-avatar-slot div[data-testid="stPopover"] button [data-testid="stIconChevronDown"],
        .header-avatar-slot div[data-testid="stPopover"] button [data-testid="stIconChevronUp"],
        .header-avatar-slot div[data-testid="stPopover"] button span:has(svg) {
            display: none !important;
            visibility: hidden !important;
            width: 0 !important;
            height: 0 !important;
        }

        .header-avatar-slot div[data-testid="stPopover"] button p,
        .header-avatar-slot div[data-testid="stPopover"] button div {
            margin: 0 !important;
            padding: 0 !important;
            font-size: 1.25rem !important;
            font-weight: 800 !important;
            line-height: 1 !important;
            font-family: 'Outfit', sans-serif !important;
            color: #ffffff !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    
    # Top bar with ONLY the circular avatar button at the top right
    top_col_spacer, top_col_avatar = st.columns([0.94, 0.06])
    
    # Select sleek emoji avatar based on role and custom settings
    if user_pic and len(user_pic) <= 4:
        avatar_emoji = user_pic
    elif user_role == "admin":
        avatar_emoji = "👑"
    elif not is_guest:
        avatar_emoji = "🛡️"
    else:
        avatar_emoji = "👤"
    
    with top_col_avatar:
        st.markdown('<div class="header-avatar-slot">', unsafe_allow_html=True)
        avatar_trigger_label = avatar_emoji
        
        with st.popover(avatar_trigger_label, use_container_width=False):
            if is_guest:
                # -------------------------------------------------------------
                # GUEST SIGN IN / REGISTRATION MODAL
                # -------------------------------------------------------------
                st.markdown(
                    '<div class="google-account-modal">'
                    '<div class="google-modal-avatar">👤</div>'
                    '<div class="google-modal-greeting">Welcome, Guest!</div>'
                    '</div>',
                    unsafe_allow_html=True
                )
                
                tab_login, tab_otp, tab_register = st.tabs([
                    "Password", "Email OTP", "Register"
                ])
                
                # Tab 1: Standard Password Sign In
                with tab_login:
                    l_user = st.text_input("Username or Email", key="hdr_login_user")
                    l_pass = st.text_input("Password", type="password", key="hdr_login_pass")
                    if st.button("Sign In", type="primary", width="stretch", key="hdr_login_btn"):
                        user_info = auth.authenticate_user(l_user, l_pass)
                        if user_info:
                            st.session_state.authenticated = True
                            st.session_state.username = user_info["username"]
                            st.session_state.user_role = user_info["role"]
                            st.session_state.intro_completed = True
                            st.session_state.pop("hdr_login_user", None)
                            st.session_state.pop("hdr_login_pass", None)
                            st.toast(f"Welcome back, {user_info['username']}!")
                            st.rerun()
                        else:
                            st.error("Invalid credentials.")

                # Tab 2: OTP Sign In
                with tab_otp:
                    st.caption("Sign in via application-generated 6-digit OTP code:")
                    h_otp_id = st.text_input("Registered Email or Username", placeholder="auditor@company.com", key="hdr_otp_id_in")
                    
                    if st.session_state.get("hdr_active_otp_id") == h_otp_id and st.session_state.get("hdr_otp_requested"):
                        st.info(f"Verification OTP code sent to owner of '{h_otp_id}'.")
                        h_user_otp = st.text_input("Enter 6-Digit OTP Code", key="hdr_user_otp_input")
                        
                        if st.button("Verify OTP & Sign In", type="primary", width="stretch", key="hdr_verify_otp_btn"):
                            ok, u_info, msg = auth.verify_email_otp(h_otp_id, h_user_otp)
                            if ok and u_info:
                                st.session_state.authenticated = True
                                st.session_state.username = u_info["username"]
                                st.session_state.user_role = u_info["role"]
                                st.session_state.intro_completed = True
                                st.session_state.pop("hdr_active_otp_id", None)
                                st.session_state.pop("hdr_otp_requested", None)
                                st.session_state.pop("hdr_otp_id_in", None)
                                st.session_state.pop("hdr_user_otp_input", None)
                                st.toast(f"OTP verified! Welcome {u_info['username']}")
                                st.rerun()
                            else:
                                st.error(msg)
                    else:
                        if st.button("Send Verification OTP", width="stretch", key="hdr_gen_otp_btn"):
                            ok, msg, _ = auth.generate_email_otp(h_otp_id)
                            if ok:
                                st.session_state["hdr_active_otp_id"] = h_otp_id
                                st.session_state["hdr_otp_requested"] = True
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)

                # Tab 3: Registration Form
                with tab_register:
                    st.caption("Create a compliance auditor account:")
                    r_fname = st.text_input("Full Name", key="hdr_reg_fname")
                    r_user = st.text_input("Username*", key="hdr_reg_user")
                    r_email = st.text_input("Work Email*", key="hdr_reg_email")
                    r_pass = st.text_input("Password*", type="password", key="hdr_reg_pass")
                    r_conf = st.text_input("Confirm Password*", type="password", key="hdr_reg_conf")
                    
                    if st.button("Create Account", type="primary", width="stretch", key="hdr_reg_btn"):
                        if not r_user or not r_pass:
                            st.error("Username and password required.")
                        elif r_pass != r_conf:
                            st.error("Passwords do not match.")
                        else:
                            ok, msg = auth.register_user(
                                username=r_user,
                                password=r_pass,
                                email=r_email,
                                full_name=r_fname,
                                role="registered",
                                auth_provider="local"
                            )
                            if ok:
                                st.success("Account created! Switch to Password tab to log in.")
                            else:
                                st.error(msg)
            else:
                # -------------------------------------------------------------
                # GOOGLE-STYLE LOGGED-IN ACCOUNT MODAL
                # -------------------------------------------------------------
                avatar_img_html = f'<img src="{user_pic}" style="width: 76px; height: 76px; border-radius: 50%; object-fit: cover; border: 3px solid #38bdf8; margin: 0 auto 10px; display: block;" />' if (user_pic and (user_pic.startswith("http://") or user_pic.startswith("https://") or user_pic.startswith("data:"))) else f'<div class="google-modal-avatar">{avatar_emoji}</div>'
                email_html = f'<div class="google-modal-email">{user_email}</div>' if user_email else ''
                
                st.markdown(
                    f'<div class="google-account-modal">{email_html}{avatar_img_html}<div class="google-modal-greeting">Hi, {display_greeting}!</div></div>',
                    unsafe_allow_html=True
                )
                
                # Collapsible Account Management (Profile & Security)
                with st.expander("Manage your Compliance Account", expanded=False):
                    tab_m_profile, tab_m_sec = st.tabs(["Profile Details", "Security"])
                    
                    with tab_m_profile:
                        st.text_input("Username", value=username, disabled=True, help="Unique username cannot be changed.")
                        new_fname = st.text_input("Full Name", value=user_prof.get("full_name", ""), key="g_edit_fname")
                        
                        # Email: Locked if verified/provided, enabled if empty
                        existing_email = (user_prof.get("email") or "").strip()
                        if existing_email:
                            st.text_input("Email Address 🔒 (Verified)", value=existing_email, disabled=True, help="Verified email address is locked for compliance integrity.")
                            final_email = existing_email
                        else:
                            final_email = st.text_input("Email Address", placeholder="auditor@company.com", key="g_edit_email", help="Enter your corporate email to associate with your profile.")
                        
                        # Phone: Locked if verified/provided, enabled if empty/not provided
                        existing_phone = (user_prof.get("phone") or "").strip()
                        if existing_phone:
                            st.text_input("Phone Number 🔒 (Verified)", value=existing_phone, disabled=True, help="Verified phone number is locked for compliance integrity.")
                            final_phone = existing_phone
                        else:
                            final_phone = st.text_input("Phone Number", placeholder="e.g. +1 (555) 019-2834", key="g_edit_phone", help="Enter contact phone number to add to your profile.")
                        
                        new_org = st.text_input("Organization", value=user_prof.get("organization", ""), key="g_edit_org")
                        new_desig = st.text_input("Designation", value=user_prof.get("designation", "") or "Auditor / Security Analyst", key="g_edit_desig")
                        new_pic = st.text_input("Avatar Photo URL or Emoji", value=user_prof.get("picture", ""), placeholder="e.g. 🛡️ or https://.../photo.png", key="g_edit_pic")
                        
                        created_date = (user_prof.get("created_at") or "")[:10]
                        if created_date:
                            st.caption(f"📅 **Member since:** {created_date}")
                        
                        if st.button("Save Profile Changes", type="primary", width="stretch", key="g_save_prof_btn"):
                            ok, msg = auth.update_user_profile(
                                username=username,
                                full_name=new_fname,
                                email=final_email,
                                phone=final_phone,
                                organization=new_org,
                                designation=new_desig,
                                picture=new_pic
                            )
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
                                
                    with tab_m_sec:
                        curr_p = st.text_input("Current Password", type="password", key="g_curr_pwd")
                        new_p = st.text_input("New Password", type="password", key="g_new_pwd")
                        conf_p = st.text_input("Confirm Password", type="password", key="g_conf_pwd")
                        if st.button("Update Password", width="stretch", key="g_update_pwd_btn"):
                            if not curr_p or not new_p:
                                st.error("Please fill all fields.")
                            elif new_p != conf_p:
                                st.error("Passwords do not match.")
                            else:
                                ok, msg = auth.update_user_password(username, curr_p, new_p)
                                if ok:
                                    st.success(msg)
                                else:
                                    st.error(msg)
                
                # Direct Centered Sign Out Action
                st.divider()
                if st.button("🚪 Sign out", key="g_signout_btn", width="stretch"):
                    st.session_state.authenticated = True
                    st.session_state.username = "guest"
                    st.session_state.user_role = "guest"
                    st.session_state.messages = []
                    st.session_state.intro_completed = True
                    st.toast("Signed out successfully.")
                    st.rerun()
                
                st.markdown(
                    """
                    <div style="text-align: center; font-size: 0.72rem; color: #64748b; margin-top: 10px;">
                        Privacy Policy • Terms of Service
                    </div>
                    """,
                    unsafe_allow_html=True
                )
