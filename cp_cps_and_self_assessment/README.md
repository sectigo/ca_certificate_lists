# CA Certificates in scope for each Sectigo CP/CPS and corresponding Self-Assessments of BR Compliance

[This CSV file](list_for_cp_cps_and_self_assessment.csv) lists all publicly-trusted Sectigo Root Certificates and the unexpired Subordinate CA Certificates beneath them, and identifies which combined CP/CPS(es) are applicable for each one:
- When `TLS?` is `TLS`, the Sectigo [TLS CP/CPS](https://www.sectigo.com/cps-repository) is applicable.
- When `S/MIME?` is `S/MIME`, the Sectigo [S/MIME CP/CPS](https://www.sectigo.com/cps-repository) is applicable.
- When `Code Signing?` is `CS`, the Sectigo [Code Signing CP/CPS](https://www.sectigo.com/cps-repository) is applicable.
- When `Document Signing?` is `DS`, the Sectigo [Document Signing CP/CPS](https://www.sectigo.com/cps-repository) is applicable.
- When `eIDAS?` is `eIDAS`, the Sectigo [eIDAS CP/CPS](https://sectigo.com/eIDASCPS) is applicable.
- When `External?` is `External`, the Subordinate CA is owned and operated by the third-party identified by the `CA Owner` field. The applicable CP/CPS(es) and Self-Assessments are not identified or provided by this repository.
