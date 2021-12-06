package com.flyingblu.certAnalysis;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.security.cert.CertificateParsingException;
import java.sql.SQLException;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;

// Objective: Analyze if the certificate can be used on the domain.
// Method: First check the common name in subject destinguished name, if not match
// then check the list of SAN to find a match. If still no match, the certificate
// is not valid for the given domain. Note that there are two types of domain names
// that should use different checking policies. The traditional domain names (only
// contain ASCII characters) and the internationalized domain names.
// For the traditional domain names, the domain name should be compared in case-
// insensitive manner.
// Limit: this algorithm only looks for exact matches, wildcards are not considered.
public class AnalyzeDomainMatch {
    public static void main(String[] args) throws SQLException, CertificateParsingException {
        final String DB_PATH = "cert.sqlite";

        int numMismatch = 0;
        final var regex = Pattern.compile("CN=([^,]*)");
        for (var certs : new DBCertFetcher(DB_PATH)) {
            boolean domainMatched = false;
            // Checking SAN for a match with the DNS name
            var SANs = certs.certs[0].getSubjectAlternativeNames();
            if (SANs != null) {
                for (var SAN : SANs) {
                    if (SAN.get(0).equals(2) && certs.domain.equalsIgnoreCase((String) SAN.get(1))) {
                        domainMatched = true;
                        break;
                    }
                }
            }
            if (domainMatched)
                continue;
            // No match in SAN, continue to match CN
            String cn = certs.certs[0].getSubjectDN().getName();
            final var matched = regex.matcher(cn).results().toArray(MatchResult[]::new);
            // Skip some certs that does not contain CN
            if (matched.length == 1 && (certs.domain.equalsIgnoreCase(matched[0].group(1))
                    || matched[0].group(1).equalsIgnoreCase("*.com")))
                continue;
            System.out.println(certs.domain);
            ++numMismatch;
        }
        System.out.println("Number of mismatch domains: " + numMismatch);
    }
}
