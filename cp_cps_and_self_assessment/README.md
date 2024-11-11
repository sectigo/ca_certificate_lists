# CA Certificates in scope for each Sectigo CP/CPS and corresponding Self-Assessments of BR Compliance

[This CSV file](list_for_cp_cps_and_self_assessment.csv) lists all publicly-trusted Sectigo Root Certificates and the unexpired Subordinate CA Certificates beneath them, and identifies which Sectigo CP(s), CPS(es), and/or combined CP/CPS(es), are applicable for each one:
- When `TLS CPS?` is `TLS`, the Sectigo [WebPKI CP and TLS CPS](https://sectigo.com/CPS) are applicable.
- When `S/MIME CPS?` is `S/MIME`, the Sectigo [WebPKI CP](https://sectigo.com/CPS) and [S/MIME CPS](https://sectigo.com/SMIMECPS) are applicable.
- When `Code Signing CPS?` is `CS`, the Sectigo [WebPKI CP and Code Signing CPS](https://sectigo.com/CPS) are applicable.
- When `eIDAS CPS?` is `eIDAS`, the Sectigo [eIDAS CP and CPS](https://sectigo.com/eIDASCPS) are applicable.
- When `Document Signing CPS?` is `DS`, the Sectigo [Document Signing CP/CPS](https://sectigo.com/CPS) is applicable.
- When `External CPS?` is `External`, the Subordinate CA is owned and operated by the third-party identified by the `CA Owner` field. The applicable CP/CPS(es) and Self-Assessments are not identified or provided by this repository.
