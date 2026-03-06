# Reporting a Vulnerability
If you believe you have found a security issue in **tss4j** or in one of its
native dependencies (GG20/FROST glue, GMP-sec wrappers, etc.) **please do not
open a public issue or pull-request.**

Instead, email us at:
`security@tkeeper.org`

Please include:

1. **Affected component / version**  
   (`frost x.x.x`, `gg20 x.x.x`, …)
2. **Impact overview**  
   *What can an attacker do?*
3. **Reproduction or PoC**  
   Minimal code, test-vector, or transcript.
4. **Suggested fix** *(optional)*

We aim to respond within **72 hours** and to release a patch within **30 days**
for critical issues. All reports are kept confidential until a coordinated
release date is agreed.

---

## Hall of Fame
We gratefully acknowledge researchers who invest their time to keep *tss4j*
secure. With permission, we list credited reporters in `CHANGELOG.md`.

---

## Disclaimer
`tss4j` mitigates timing/cache side-channels at the *software* level.
Physical emanations (EM/power) and a compromised operating-system RNG remain
out-of-scope.