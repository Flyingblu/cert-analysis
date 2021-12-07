package com.flyingblu.certAnalysis;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * Objective: Validate the certificate.
 * Method: First check whether certificate chain can be trusted or not with the
 * Mozilla Firefox's trust anchors. Then for the trusted certificate chains, check
 * if there are any certificate revoked by the CRL (can analyze the level of revoked
 * certificates).
 * Note: trusted CA certificates retrieved on 06/12/2021 from Mozilla Firefox
 */
public class AnalyzeCertChain {
    public static void main(String[] args) throws SQLException, CertificateException, IOException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {
        final String DB_PATH = "cert.sqlite";
        final String KEYSTORE_PATH = "mozilla-truststore.p12";
        final String KEYSTORE_PASSWD = "cafe-babe";
        final String CSV_FILE_PATH = "AnalyzeCertChain.csv";
        final String[] CSV_HEADER = {"Error", "Count"};

        final KeyStore ks = keyStoreUtil.loadKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWD);
        CertPathValidator cpValidator = CertPathValidator.getInstance("PKIX");
        PKIXParameters params = new PKIXParameters(ks);
        // The revocation status will be validated manually
        params.setRevocationEnabled(false);
        final var errs = new HashMap<String, Integer>();

        for (var certs : new DBCertFetcher(DB_PATH)) {
            // Check if is trusted
            final var certPath = CertUtil.getCertPathFromArray(certs.certs);
            try {
                final var result = (PKIXCertPathValidatorResult) cpValidator.validate(certPath, params);
                errs.put("TRUSTPASS", errs.getOrDefault("TRUSTPASS", 0) + 1);
            } catch (CertPathValidatorException e) {
                errs.put(e.toString(), errs.getOrDefault(e.toString(), 0) + 1);
            }
        }

        // Output results
        try (final var fw = new FileWriter(CSV_FILE_PATH);
             final var csvPrinter = new CSVPrinter(fw, CSVFormat.Builder.create().setHeader(CSV_HEADER).build())) {
            errs.forEach((err, cnt) -> {
                try {
                    csvPrinter.printRecord(err, cnt);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }
    }
}
