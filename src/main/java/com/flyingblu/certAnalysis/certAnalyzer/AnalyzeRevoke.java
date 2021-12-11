package com.flyingblu.certAnalysis.certAnalyzer;

import com.flyingblu.certAnalysis.cert.CertRevocationChecker;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.sql.Array;
import java.sql.SQLException;
import java.util.*;

/**
 * Ojbective: Analyze the presense of CRL and OCSP in trusted certificates(
 * can divided into server certs and intermediate CA certs). Check cert
 * revocation (can also divided into two categories to analyze).
 * Method: cache the CRL list for better efficiency.
 * Reference:
 * Difference between CRL and OCSP:
 * https://docs.microfocus.com/NNMi/10.30/Content/Administer/NNMi_Deployment/Advanced_Configurations/Cert_Validation_CRL_and_OCSP.htm
 * Steps:
 * 1. Cache all trusted cert domains into a file
 * 2. modify cert fetcher to only get trusted certs
 * 3. Analyze the presence of CRL and OCSP extensions in non-root certificates
 * 4. Use CRL to check revocation status of non-root certificates
 * 5. Analyze the revocation status of non-root certificates
 * Result: saved in CSV, the program consumed around 10gigs of memory
 */
public class AnalyzeRevoke {
    public static void main(String[] args) throws SQLException, IOException, CertificateException, CRLException {
        final String DB_PATH = "cert.sqlite";
        final String TRUST_DOMAIN_PATH = "trusted-domains.txt";

        int serverNoCRL = 0, intermediateNoCRL = 0, serverNoOCSP = 0, intermediateNoOCSP = 0,
                serverNoCO = 0, intermediateNoCO = 0;
        final var serverRevokeDomains = new ArrayList<String>();
        final var interRevokeDomains = new ArrayList<String>();
        final var crc = new CertRevocationChecker();
        for (var certs : new DBCertFetcher(DB_PATH, TRUST_DOMAIN_PATH)) {
            for (int lvl = 0; lvl < certs.certs.length; ++lvl) {
                final var cert = certs.certs[lvl];

                // Ignore root certificates, which do not have revocation status
                if (cert.getSubjectDN().equals(cert.getIssuerDN()))
                    continue;

                // Checks for CRL
                List<String> crlURI = CertRevocationChecker.getCRLURI(cert);

                // Checks for OCSP
                String ocspURI = CertRevocationChecker.getOCSPURI(cert);

                // Use CRL to check revocation status
                if (crc.checkCRLRevocation(crlURI, cert)) {
                    if (lvl == 0) {
                        serverRevokeDomains.add(certs.domain);
                    } else {
                        interRevokeDomains.add(certs.domain);
                    }
                }

                if (ocspURI == null || crlURI.size() == 0) {
                    if (lvl == 0) {
                        if (ocspURI == null && crlURI.size() != 0) {
                            ++serverNoOCSP;
                        } else if (crlURI.size() == 0 && ocspURI != null) {
                            ++serverNoCRL;
                        } else {
                            ++serverNoCO;
                        }
                    } else {
                        if (ocspURI == null && crlURI.size() != 0) {
                            ++intermediateNoOCSP;
                        } else if (crlURI.size() == 0 && ocspURI != null) {
                            ++intermediateNoCRL;
                        } else {
                            ++intermediateNoCO;
                        }
                    }
                }
            }
        }

        try (final var sr = new PrintWriter("server-revoked.txt");
                final var ir = new PrintWriter("inter-revoked.txt");) {
            serverRevokeDomains.forEach(sr::println);
            interRevokeDomains.forEach(ir::println);
        }

        System.out.printf("Server no CRL: %d || Intermediate CA no CRL: %d\n", serverNoCRL, intermediateNoCRL);
        System.out.printf("Server no OCSP: %d ||Intermediate CA no OCSP: %d\n", serverNoOCSP, intermediateNoOCSP);
        System.out.printf("Server no both: %d || Intermediate CA no both: %d\n", serverNoCO, intermediateNoCO);
    }
}
