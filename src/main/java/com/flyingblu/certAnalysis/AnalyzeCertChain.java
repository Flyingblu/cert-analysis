package com.flyingblu.certAnalysis;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * Note: trusted CA certificates retrieved on 06/12/2021 from Mozilla Firefox
 */
public class AnalyzeCertChain {
    public static void main(String[] args) throws SQLException {
        final String DB_PATH = "cert.sqlite";
        for (var certs : new DBCertFetcher(DB_PATH)) {
        }
    }
}
