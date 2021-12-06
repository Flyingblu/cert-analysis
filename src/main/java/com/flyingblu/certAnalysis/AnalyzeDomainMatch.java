package com.flyingblu.certAnalysis;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.security.DomainCombiner;
import java.security.cert.CertificateParsingException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.regex.Pattern;

// Objective: Analyze if the certificate can be used on the domain.
// Method: First check the common name in subject destinguished name, if not match
// then check the list of SAN to find a match. If still no match, the certificate
// is not valid for the given domain.
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
                    if (SAN.get(0).equals(2) && SAN.get(1).equals(certs.domain)) {
                        domainMatched = true;
                        break;
                    }
                }
            }
            if (domainMatched)
                continue;
            // No match in SAN, continue to match CN
            String cn = certs.certs[0].getSubjectDN().getName();
            final var matched = regex.matcher(cn).results().toArray();
            // Skip some certs that does not contain CN
            if (matched.length == 1 && matched[0].equals(certs.domain))
                continue;
            System.out.println(certs.domain);
            ++numMismatch;
        }
        System.out.println("Number of mismatch domains: " + numMismatch);
    }
}
