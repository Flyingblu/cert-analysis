package com.flyingblu.certAnalysis.certAnalyzer;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.sql.*;
import java.util.HashMap;

public class AnalyzeCert {
    public static void main(String[] args) throws SQLException {
        final String DB_PATH = "cert.sqlite";

        // Sample task. Copy and paste this file to create your own.
        final var version = new HashMap<String, Integer>();
        for (var certs : new DBCertFetcher(DB_PATH)) {
            for (var cert : certs.certs)
                version.put(cert.getSigAlgName(), version.getOrDefault(cert.getSigAlgName(), 0) + 1);
        }
        System.out.println(version);
    }
}
