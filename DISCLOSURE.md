# Fluxgate Responsible Disclosure Protocol

When Fluxgate's batch scanning identifies vulnerable workflows in
public repositories, we follow this responsible disclosure process:

## Timeline
1. **Day 0:** Finding identified during batch scan
2. **Day 1-3:** Finding verified manually (not a false positive)
3. **Day 3-7:** Maintainer contacted via:
   - Repository SECURITY.md contact (preferred)
   - Security advisory on the repository (if enabled)
   - Direct email to listed maintainers (fallback)
4. **Day 7:** Confirmation of receipt requested
5. **Day 37:** If no response, second notification attempt
6. **Day 67:** Public disclosure of aggregate statistics
   (vulnerable repos are NOT named if unpatched)

## What We Disclose Publicly
- Aggregate statistics (X of Y repos affected)
- Rule descriptions and detection logic
- Example vulnerable patterns (synthetic, not from real repos)
- Remediation guidance

## What We Do NOT Disclose Publicly
- Names of affected repositories (until patched or 90-day window expires)
- Specific workflow file contents from unpatched repos
- Details that would enable exploitation

## Exceptions
- If a vulnerability is already being actively exploited in the wild
  (as with the Trivy compromise), we may accelerate the timeline
- If a maintainer requests extended time, we will accommodate up to
  180 days for complex remediations

## Contact
If you believe Fluxgate has identified a vulnerability in your
repository and you'd like to coordinate, contact:
christopherdlusk@gmail.com or open a GitHub Security Advisory.
