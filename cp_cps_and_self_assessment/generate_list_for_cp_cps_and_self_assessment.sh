#!/bin/bash

# All public Sectigo root and intermediate certificates are submitted to at least 1 CT log (even when no browser policy demands this) and hence are known to crt.sh.
# This script uses the public crt.sh database to report on which Sectigo root and intermediate certificates are in scope for each Self-Assessment to be provided to the root programs via the CCADB.
#
# psql doesn't support multi-line \COPY statements, so we use the HEREDOC workaround described by https://minhajuddin.com/2017/05/18/how-to-pass-a-multi-line-copy-sql-to-psql/
#
# Since long-running crt.sh:5432 queries are often killed off for various reasons, this script makes multiple attempts.  If all of the attempts fail, try running this script again later.

ERRORFILE=`mktemp`

TIMESTAMP=`date -Iseconds | sed "s/+00:00$/Z/g"`

for i in {1..10}; do
  cat <<SQL | tr -d '\n' | psql -h crt.sh -p 5432 -U guest -d certwatch -v ON_ERROR_STOP=1 -X 2>$ERRORFILE
\COPY (
WITH sectigo_ca AS (
  SELECT ca.PUBLIC_KEY AS ROOT_PUBLIC_KEY,
         c.ISSUER_CA_ID AS ROOT_CA_ID,
         c.CERTIFICATE AS SUB_CERTIFICATE,
         cac.CA_ID AS SUB_CA_ID,
         cc.CERT_NAME AS SUB_CERT_NAME,
         cc.INCLUDED_CERTIFICATE_OWNER,
         cc.SUBORDINATE_CA_OWNER,
         coalesce(cc.CP_CPS_URL, cc.CPS_URL) AS CPS_URL
    FROM ca
           JOIN certificate c ON (
             ca.ID = c.ISSUER_CA_ID
             AND x509_canIssueCerts(c.CERTIFICATE)
           )
           JOIN ca_certificate cac ON (
             c.ID = cac.CERTIFICATE_ID
           )
           LEFT JOIN ccadb_certificate cc ON (
             cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
           )
    WHERE digest(ca.PUBLIC_KEY, 'sha256') IN (
      E'\\\\x1EA3C5E43ED66C2DA2983A42A4A79B1E906786CE9F1B58621419A00463A87D38',  /* Entrust.net Certification Authority (2048) */
      E'\\\\x1FE851D6D28421FBAEA0714A85C5E63CBE46E1977B2F37B95C8EDEBE08D64B50',  /* Entrust Code Signing Root Certification Authority - CSBR1 */
      E'\\\\xDDEDA8653AC4B1C5576E9E727E8A5E9B943BD8DE1F21698BBEC86F3F7B0D22B1',  /* Entrust Digital Signing Root Certification Authority - DSR1 */
      E'\\\\x6DBFAE00D37B9CD73F8FB47DE65917AF00E0DDDF42DBCEAC20C17C0275EE2095',  /* Entrust Root Certification Authority */
      E'\\\\xFEA2B7D645FBA73D753C1EC9A7870C40E1F7B0C561E927B985BF711866E36F22',  /* Entrust Root Certification Authority - EC1 */
      E'\\\\x76EE8590374C715437BBCA6BBA6028EADDE2DC6DBBB8C3F610E851F11D1AB7F5',  /* Entrust Root Certification Authority - G2 */
      E'\\\\x36D7C79F3D089A0FF79972D90923DEA5CA76B4CCBAF7C2751CB152E9494F52D0',  /* Entrust Root Certification Authority - G4 */
      E'\\\\xE4A6C09C5F757775AB533C844FEEBFDF7761EF565F2BC95233BC33728B296E0E',  /* Entrust SMIME Root CA - 2022 */
      E'\\\\x6283D2CDAAC34F0690FFD3D51C8B9F98419CD617CFB0FEE01197BCF241ED3886',  /* Entrust Verified Mark Root Certification Authority - VMCR1 */
      E'\\\\x2DA8F9EA3454D21146464A3F9D028DC4C7FBB57B1C52C73C2B0572A2F599A2D3',  /* UTN-USERFirst-Client Authentication and Email */
      E'\\\\x4D40E7AF4304A09DE87FBF9896204C055141E3F809B2FE733BB2310FDF98A162',  /* UTN-USERFirst-Hardware */
      E'\\\\x0FE14C264B17BB6F0D653E7A70EB363DBF54BE158039EDDAE5C25711DF48C103',  /* UTN-USERFirst-Object */
      E'\\\\x4002FCD311D07331567E71BCD971E46048C8DCE8D1659711753B3DAA2A269AFA',  /* UTN - DATACorp SGC */
      E'\\\\x052B687107EC84E8730382452EC2A27451745D7485A57D6F464E0DA7A1B6AF2A',  /* AddTrust Class 1 CA Root */
      E'\\\\x942A6916A6E4AE527711C5450247A2A74FB8E156A8254CA66E739A11493BB445',  /* AddTrust External CA Root */
      E'\\\\x3861D7B6961FCDB2120456FF6FC2EB7704B1A741B4BD933A8376F5E1915CA698',  /* AddTrust Public CA Root */
      E'\\\\xC73AFC2EBA770D0CBC1EE41F252B52E8A93D12B72DCCEC031D8D839CBF818A79',  /* AddTrust Qualified CA Root */
      E'\\\\xBD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3',  /* AAA Certificate Services */
      E'\\\\x4691CBFDE84A6B6052DDBE152BB0C216AE25A86E5747813DBC0F147F338570BE',  /* Secure Certificate Services */
      E'\\\\xE2D891EFB738669105D530DE5ED72E2B2AC3F4A67078B5349B3FDACA496F5EB8',  /* Trusted Certificate Services */
      E'\\\\x006D7BE7555DD82026442C4F1A27A80E89A1989CB87B34448ED2194C18196D5E',  /* COMODO Certification Authority */
      E'\\\\x82B5F84DAF47A59C7AB521E4982AEFA40A53406A3AEC26039EFA6B2E0E7244C1',  /* COMODO RSA Certification Authority */
      E'\\\\xE7CA91BBFBB18788057B3A8070446EA5291160194102F7DCC3B9848C63CB9CD5',  /* COMODO ECC Certification Authority */
      E'\\\\xC784333D20BCD742B9FDC3236F4E509B8937070E73067E254DD3BF9C45BF4DDE',  /* USERTrust RSA Certification Authority */
      E'\\\\x2021917E98263945C859C43F1D73CB4139053C414FA03CA3BC7EE88614298F3B',  /* USERTrust ECC Certification Authority */
      E'\\\\xA05173F9D35757117666D5975177C5325DDB7165A5238DCBE092E121E98F377C',  /* Ensured Root CA */
      E'\\\\x58834D7F17AE7CF3E6F66E8FC0BE675DEF9B4BBB209769A9CAAC1AFEDD15138A',  /* Ensured Root CA (old) */
      E'\\\\x0E8BB18BBEEFB381BE21BFC1A206D317298462AD104855F04A0542699708D3D4',  /* Sectigo Public Server Authentication Root R46 */
      E'\\\\x1EBBBB91877F315B3214C972148B4D9C9CA2DCB306F06D6655642824BEC51A25',  /* Sectigo Public Email Protection Root R46 */
      E'\\\\x3537D13105F4518B938439CA8A91363E4DA3AAAD5B7A8EB15A66E7B64156BF91',  /* Sectigo Public Code Signing Root R46 */
      E'\\\\xA4DB8668C6796EBF476DDC5ACE453A9260DBD4DBB09F51ECEC9A839003824795',  /* Sectigo Public Time Stamping Root R46 */
      E'\\\\x29472BD6CC54563D2A9C454BA95322864FAEC99B0C07865758DDE37E3F10D7CC',  /* Sectigo Public Document Signing Root R46 */
      E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
      E'\\\\xB0B56335468561F5BB9FA12D801784A633A572705D34F32B643445DFA8B005D1',  /* Sectigo Public Server Authentication Root E46 */
      E'\\\\x9710F2D0872D46BFB5CE50AFE7EDC362C119227B351B57E282F1AAF9C6D2DE8D',  /* Sectigo Public Email Protection Root E46 */
      E'\\\\x1679B889B408FD06CE0E96994D2C47AA35CAE25562A6B9A2E5574D2598BCA0D8',  /* Sectigo Public Code Signing Root E46 */
      E'\\\\xC39EE6DDCC1F6C0179D9F4584D08CD4926A9F1350CB09B3F5AA435F41F4CA1EB',  /* Sectigo Public Time Stamping Root E46 */
      E'\\\\x5842C9C71852647D253475BE59CD43969A59B2E86D01E63B4BC529294D644D64',  /* Sectigo Public Document Signing Root E46 */
      E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9',  /* Sectigo Public Root E46 */
      E'\\\\x60181E5DCA7F32C0624A38328BB03E26D833EC26B2B055246650C4CED4CEE966',  /* Sectigo Qualified Legal Person Root R45 */
      E'\\\\xBCC15F470BBD39F510FAF40537AE490CDA91261B80EEC2E6198802C21F696C51',  /* Sectigo Qualified Natural Person Root R45 */
      E'\\\\x249A62465E28D403786FD9C9517E89052AE36F3A3610DC196505E56C38EA4CA7',  /* Sectigo Qualified Time Stamping Root R45 */
      E'\\\\xD66EA3AF34602C6A84AEB342D06E09A9BBC2CE0262BA496713EB8BAEC14EAF26',  /* Sectigo Qualified Legal Person Root E45 */
      E'\\\\x84C0A056345DC9DDC0B42BE4A4B3F66BA538F18552EB058E710F92E05C05721E'   /* Sectigo Qualified Natural Person Root E45 */
    )
      AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::date) >= now() AT TIME ZONE 'UTC'
      AND (
        cc.INCLUDED_CERTIFICATE_OWNER LIKE 'Sectigo%'
        OR cc.SUBORDINATE_CA_OWNER LIKE 'Sectigo%'
        OR cc.CERT_NAME LIKE '%Sectigo%'
      )
)
SELECT CASE WHEN sc.ROOT_CA_ID = sc.SUB_CA_ID THEN 'Root' ELSE 'Intermediate' END AS "CA Certificate Type",
       x509_issuerName(sc.SUB_CERTIFICATE, 1310736) AS "Issuer DN",
       x509_subjectName(sc.SUB_CERTIFICATE, 1310736) AS "Subject DN",
       upper(encode(digest(sc.SUB_CERTIFICATE, 'sha256'), 'hex')) AS "SHA-256(Certificate)",
       upper(encode(digest(x509_publicKey(sc.SUB_CERTIFICATE), 'sha256'), 'hex')) AS "SHA-256(SubjectPublicKeyInfo)",
       x509_notBefore(sc.SUB_CERTIFICATE) AS "Not Before",
       x509_notAfter(sc.SUB_CERTIFICATE) AS "Not After",
       CASE WHEN now() AT TIME ZONE 'UTC' > x509_notAfter(sc.SUB_CERTIFICATE) THEN 'Yes' ELSE 'No' END AS "Expired (checked at <timestamp>)?",
       CASE WHEN cr.SERIAL_NUMBER IS NOT NULL THEN 'Yes' ELSE 'No' END AS "Revoked (checked at <timestamp>)?",
       coalesce(coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), sc.INCLUDED_CERTIFICATE_OWNER), 'Sectigo') AS "CA Owner",
       CASE WHEN
           /* TLS CPS covers all CAs capable of and/or intended for Server Authentication, excluding eIDAS and externally-operated CAs */
           (ctp_tls.TRUST_PURPOSE_ID IS NOT NULL)
           AND (lower(coalesce(sc.CPS_URL, '')) NOT LIKE '%eidas%')
           AND (coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), 'Sectigo') LIKE 'Sectigo%')
         THEN 'TLS' ELSE 'n/a' END AS "TLS?",
       CASE WHEN
           /* S/MIME CPS covers all CAs capable of and/or intended for Secure Email, excluding eIDAS and externally-operated CAs */
           (ctp_smime.TRUST_PURPOSE_ID IS NOT NULL)
           AND (lower(coalesce(sc.CPS_URL, '')) NOT LIKE '%eidas%')
           AND (coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), 'Sectigo') LIKE 'Sectigo%')
         THEN 'S/MIME' ELSE 'n/a' END AS "S/MIME?",
       CASE WHEN
           /* Code Signing CPS covers all CAs capable of and/or intended for Code Signing and/or Time Stamping, excluding eIDAS and externally-operated CAs */
           (ctp_codesigning.TRUST_PURPOSE_ID IS NOT NULL)
           AND (lower(coalesce(sc.CPS_URL, '')) NOT LIKE '%eidas%')
           AND (coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), 'Sectigo') LIKE 'Sectigo%')
         THEN 'CS' ELSE 'n/a' END AS "Code Signing?",
       CASE WHEN
           /* eIDAS CPS, excluding externally-operated CAs */
           ((lower(sc.CPS_URL) LIKE '%eidas%') OR (sc.SUB_CERT_NAME LIKE 'Sectigo Qualified%'))
           AND (coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), 'Sectigo') LIKE 'Sectigo%')
         THEN 'eIDAS' ELSE 'n/a' END AS "eIDAS?",
       CASE WHEN
           /* Document Signing CPS covers all CAs capable of and/or intended for Document Signing and/or Time Stamping, excluding eIDAS and externally-operated CAs */
           (ctp_docsigning.TRUST_PURPOSE_ID IS NOT NULL)
           AND (lower(coalesce(sc.CPS_URL, '')) NOT LIKE '%eidas%')
           AND (coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), 'Sectigo') LIKE 'Sectigo%')
         THEN 'DS' ELSE 'n/a' END AS "Document Signing?",
       CASE WHEN
           /* Anything externally-operated is not governed by a Sectigo-controlled CPS */
           coalesce(nullif(sc.SUBORDINATE_CA_OWNER, ''), 'Sectigo') NOT LIKE 'Sectigo%'
         THEN 'External' ELSE 'n/a' END AS "External?",
       upper(encode(x509_serialNumber(sc.SUB_CERTIFICATE), 'hex')) AS "Serial Number",
       upper(encode(x509_subjectKeyIdentifier(sc.SUB_CERTIFICATE), 'hex')) AS "Subject Key Identifier"
  FROM sectigo_ca sc
         LEFT JOIN crl_revoked cr ON (
           sc.ROOT_CA_ID = cr.CA_ID
           AND x509_serialNumber(sc.SUB_CERTIFICATE) = cr.SERIAL_NUMBER
         )
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(sc.ROOT_PUBLIC_KEY, 'sha256') IN (
                         /* These multi-purpose Sectigo Public Roots are "intended" (although hopefully we will never have to use them) to be, but are not yet, trusted */
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 1
                       ELSE max(ctp1.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp1, trust_purpose tp1
             WHERE ctp1.CA_ID = sc.SUB_CA_ID
               AND ctp1.TRUST_CONTEXT_ID != 23  /* Ignore the Java root store, which enables all roots for all purposes */
               AND ctp1.TRUST_PURPOSE_ID = 1  /* Server Authentication */
               AND ctp1.TRUST_PURPOSE_ID = tp1.ID
               AND x509_isEKUPermitted(sc.SUB_CERTIFICATE, tp1.PURPOSE_OID)
               AND NOT sc.SUB_CERT_NAME LIKE 'Sectigo Qualified%'
         ) ctp_tls ON TRUE
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(sc.ROOT_PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 3  /* These multi-purpose Sectigo Public Roots are "intended" (although hopefully we will never have to use them) to be, but are not yet, trusted for Secure Email */
                       ELSE max(ctp2.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp2, trust_purpose tp1
             WHERE ctp2.CA_ID = sc.SUB_CA_ID
               AND ctp2.TRUST_CONTEXT_ID != 23  /* Ignore the Java root store, which enables all roots for all purposes */
               AND ctp2.TRUST_PURPOSE_ID = 3  /* Secure Email */
               AND ctp2.TRUST_PURPOSE_ID = tp1.ID
               AND x509_isEKUPermitted(sc.SUB_CERTIFICATE, tp1.PURPOSE_OID)
               AND NOT sc.SUB_CERT_NAME LIKE 'Sectigo Qualified%'
         ) ctp_smime ON TRUE
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(sc.ROOT_PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 4  /* These multi-purpose Sectigo Public Roots are "intended" (although hopefully we will never have to use them) to be, but are not yet, trusted for Code Signing and/or Time Stamping */
                       ELSE max(ctp3.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp3, trust_purpose tp1
             WHERE ctp3.CA_ID = sc.SUB_CA_ID
               AND ctp3.TRUST_CONTEXT_ID != 23  /* Ignore the Java root store, which enables all roots for all purposes */
               AND ctp3.TRUST_PURPOSE_ID IN (4, 5)  /* Code Signing, Time Stamping */
               AND ctp3.TRUST_PURPOSE_ID = tp1.ID
               AND x509_isEKUPermitted(sc.SUB_CERTIFICATE, tp1.PURPOSE_OID)
               AND NOT sc.SUB_CERT_NAME LIKE 'Sectigo Qualified%'
         ) ctp_codesigning ON TRUE
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(sc.ROOT_PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 7  /* These multi-purpose Sectigo Public Roots are "intended" (although hopefully we will never have to use them) to be, but are not yet, trusted for Document Signing and/or Time Stamping */
                       ELSE max(ctp4.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp4, trust_purpose tp1
             WHERE ctp4.CA_ID = sc.SUB_CA_ID
               AND ctp4.TRUST_CONTEXT_ID != 23  /* Ignore the Java root store, which enables all roots for all purposes */
               AND ctp4.TRUST_PURPOSE_ID IN (7, 5, 14)  /* Document Signing, Time Stamping, Adobe Authentic Document */
               AND ctp4.TRUST_PURPOSE_ID = tp1.ID
               AND x509_isEKUPermitted(sc.SUB_CERTIFICATE, tp1.PURPOSE_OID)
               AND NOT sc.SUB_CERT_NAME LIKE 'Sectigo Qualified%'
         ) ctp_docsigning ON TRUE
  GROUP BY sc.SUB_CERTIFICATE, "Issuer DN", "CA Certificate Type", "Subject DN", "Not Before", "Not After", digest(sc.ROOT_PUBLIC_KEY, 'sha256'), "SHA-256(Certificate)", cr.SERIAL_NUMBER, "CA Owner", "TLS?", "S/MIME?", "Code Signing?", "eIDAS?", "Document Signing?", "External?", "Serial Number", "Subject Key Identifier"
  ORDER BY "Issuer DN", "CA Certificate Type" DESC, "Subject DN", "Not Before", "Not After", digest(sc.ROOT_PUBLIC_KEY, 'sha256'), "SHA-256(Certificate)"
) TO 'list_for_cp_cps_and_self_assessment.csv' CSV HEADER
SQL

  RESULT=$?
  cat $ERRORFILE
  echo "[Attempt $i]: psql returned $RESULT (expecting 0)."
  if [ "$RESULT" -eq "0" ]; then
    grep ERROR $ERRORFILE >/dev/null
    RESULT=$?
    echo "[Attempt $i]: \"grep ERROR\" returned $RESULT (expecting !=0)."
    if [ "$RESULT" -ne "0" ]; then
      sed -i "s/<timestamp>/$TIMESTAMP/g" list_for_cp_cps_and_self_assessment.csv
      break
    fi
  fi
  echo
done

rm -f $ERRORFILE
