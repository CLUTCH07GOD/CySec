# NIST SP 800-63B Revision 4 (2025) Reference Document

## Key Requirements:
1. **Password Length Floor:** Minimum 15 characters for single-factor authentication, minimum 8 characters when used with Multi-Factor Authentication (MFA).
2. **Maximum Length:** Maximum length up to 64 characters.
3. **Prohibition of Outdated Composition Rules:** Systems MUST NOT require character composition mixtures (forcing uppercase, numbers, or special characters).
4. **Mandatory Breach Blocklist Screening:** Passwords must be verified against compromised credential lists (e.g., Have I Been Pwned k-anonymity API).
5. **No Forced Expiration:** Mandatory periodic password rotation is explicitly prohibited unless a breach is suspected.
