#!/bin/bash

# All public Sectigo root and intermediate certificates are submitted to at least 1 CT log (even when no browser policy demands this) and hence are known to crt.sh.
# This script uses the public crt.sh database to report all in-scope Sectigo root and intermediate certificates for the specified WebTrust audit period.
#
# psql doesn't support multi-line \COPY statements, so we use the HEREDOC workaround described by https://minhajuddin.com/2017/05/18/how-to-pass-a-multi-line-copy-sql-to-psql/
#
# If any of the following errors occur, simply try running this script again.
#   1. ERROR:  canceling statement due to conflict with recovery
#      DETAIL:  User query might have needed to see row versions that must be removed.
#   2. ERROR:  no more connections allowed (max_client_conn)

ERRORFILE=`mktemp`

for i in {1..10}; do
  cat <<SQL | tr -d '\n' | psql -h crt.sh -p 5432 -U guest -d certwatch -v ON_ERROR_STOP=1 -X 2>$ERRORFILE
\COPY (
SELECT CASE WHEN c.ISSUER_CA_ID = cac.CA_ID THEN 'Root' ELSE 'Intermediate' END AS "CA Certificate Type",
       get_ca_name_attribute(ca.ID) AS "Issuer Common Name",
       x509_subjectName(c.CERTIFICATE, 1310736) AS "Subject DN",
       upper(encode(digest(c.CERTIFICATE, 'sha256'), 'hex')) AS "SHA-256(Certificate)",
       x509_notBefore(c.CERTIFICATE) AS "Not Before",
       x509_notAfter(c.CERTIFICATE) AS "Not After",
       coalesce(coalesce(nullif(cc.SUBORDINATE_CA_OWNER, ''), cc.INCLUDED_CERTIFICATE_OWNER), 'Sectigo') AS "CA Owner",
       'CA' AS "WTCA?",
       'NETSEC' AS "WTNETSEC?",
       CASE WHEN (ctp_brssl.TRUST_PURPOSE_ID IS NULL) THEN 'n/a' ELSE 'BRSSL' END AS "WTBRSSL?",
       CASE WHEN ((ctp_brssl.TRUST_PURPOSE_ID IS NULL) OR (ctp_evssl.TRUST_PURPOSE_ID IS NULL)) THEN 'n/a' ELSE 'EVSSL' END AS "WTEVSSL?",
       CASE WHEN (ctp_cs.TRUST_PURPOSE_ID IS NULL) THEN 'n/a' ELSE 'CS' END AS "WTCS?",
       CASE WHEN (ctp_smime.TRUST_PURPOSE_ID IS NULL) THEN 'n/a' ELSE 'SMIME' END AS "WTSMIME?",
       upper(encode(x509_serialNumber(c.CERTIFICATE), 'hex')) AS "Serial Number",
       upper(encode(x509_subjectKeyIdentifier(c.CERTIFICATE), 'hex')) AS "Subject Key Identifier"
  FROM ca,
       certificate c,
       ca_certificate cac
         LEFT JOIN ccadb_certificate cc ON (
           cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
         )
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(ca.PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 1  /* These Sectigo Public hierarchies are intended to be considered as trusted for Server Authentication */
                       ELSE max(ctp1.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp1, trust_purpose tp1
             WHERE ctp1.CA_ID = cac.CA_ID
               AND ctp1.TRUST_PURPOSE_ID = 1  /* Server Authentication */
               AND ctp1.TRUST_PURPOSE_ID = tp1.ID
               AND (
                 x509_isEKUPermitted(c.CERTIFICATE, tp1.PURPOSE_OID)
                 OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')  /* Microsoft SGC */
                 OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')  /* Netscape Step-Up */
               )
         ) ctp_brssl ON TRUE
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(ca.PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 121  /* These Sectigo Public hierarchies are intended to be considered as trusted for Server Authentication */
                       ELSE max(ctp2.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp2, trust_purpose tp2
             WHERE ctp2.CA_ID = cac.CA_ID
               AND ctp2.TRUST_PURPOSE_ID >= 100
               AND ctp2.TRUST_PURPOSE_ID = tp2.ID
               AND x509_isPolicyPermitted(c.CERTIFICATE, tp2.PURPOSE_OID)  /* A specific EV Policy OID */
         ) ctp_evssl ON TRUE
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(ca.PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 4  /* These Sectigo Public hierarchies are intended, but not yet trusted, for Code Signing */
                       WHEN digest(ca.PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 5  /* These Sectigo Public hierarchies are intended to be considered as trusted for Time Stamping */
                       ELSE max(ctp3.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp3, trust_purpose tp3
             WHERE ctp3.CA_ID = cac.CA_ID
               AND ctp3.TRUST_PURPOSE_ID IN (4, 5)  /* Code Signing, Time Stamping */
               AND ctp3.TRUST_PURPOSE_ID = tp3.ID
               AND x509_isEKUPermitted(c.CERTIFICATE, tp3.PURPOSE_OID)
         ) ctp_cs ON TRUE
         LEFT JOIN LATERAL (
           SELECT CASE WHEN digest(ca.PUBLIC_KEY, 'sha256') IN (
                         E'\\\\x94960A01B0B5EEEE029AF6E83B61CE8146BEA51DA7566E2D3485EF7BF90B78FD',  /* Sectigo Public Root R46 */
                         E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
                       ) THEN 3  /* These Sectigo Public hierarchies are intended to be considered as trusted for Email Protection */
                       ELSE max(ctp4.TRUST_PURPOSE_ID)
                  END AS TRUST_PURPOSE_ID
             FROM ca_trust_purpose ctp4, trust_purpose tp4
             WHERE ctp4.CA_ID = cac.CA_ID
               AND ctp4.TRUST_PURPOSE_ID = 3  /* Email Protection */
               AND ctp4.TRUST_PURPOSE_ID = tp4.ID
               AND x509_isEKUPermitted(c.CERTIFICATE, tp4.PURPOSE_OID)
         ) ctp_smime ON TRUE
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
      E'\\\\x8674E7A6B729A1375D9BF2FCEEC5D12F7EF73FFD09F452E4905B2213052A17B9'   /* Sectigo Public Root E46 */
    )
    AND ca.ID = c.ISSUER_CA_ID
    AND x509_canIssueCerts(c.CERTIFICATE)
    AND c.ID = cac.CERTIFICATE_ID
    AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::date) >= '2024-04-01'::date
    AND x509_notBefore(c.CERTIFICATE) < '2025-04-01'::date
  GROUP BY "Issuer Common Name", "CA Certificate Type", x509_subjectName(c.CERTIFICATE, 1310736), "Not Before", "Not After", digest(ca.PUBLIC_KEY, 'sha256'), digest(c.CERTIFICATE, 'sha256'), "CA Owner", "WTCA?", "WTNETSEC?", "WTBRSSL?", "WTEVSSL?", "WTCS?", "WTSMIME?", "Serial Number", "Subject Key Identifier"
  ORDER BY "Issuer Common Name", "CA Certificate Type" DESC, x509_subjectName(c.CERTIFICATE, 1310736), "Not Before", "Not After", digest(ca.PUBLIC_KEY, 'sha256'), digest(c.CERTIFICATE, 'sha256')
) TO 'list_for_audit.csv' CSV HEADER
SQL

  RESULT=$?
  echo "[Attempt $i]: psql returned $RESULT."
  if [ "$RESULT" -eq "0" ]; then
    grep ERROR $ERRORFILE >/dev/null
    RESULT=$?
    echo "[Attempt $i]: \"grep ERROR\" returned $RESULT."
    if [ "$RESULT" -ne "0" ]; then
      break
    fi
  fi
done

rm -f $ERRORFILE
