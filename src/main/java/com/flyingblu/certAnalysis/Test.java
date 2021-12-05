package com.flyingblu.certAnalysis;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.sql.SQLException;

public class Test {
    public static void main(String[] args) throws IOException, ParseException, SQLException, CertificateException {
        final var fetcher = new DBCertFetcher("cert.sqlite");
        for (var cert: fetcher) {
        }
    }
}
