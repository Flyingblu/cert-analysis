package com.flyingblu.certAnalysis;

import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.Deque;

public class AnalyzeCert {
    public static void main(String[] args) throws ParseException, SQLException, CertificateException {
        final Options options = new Options();
        options.addOption("n", "number", true, "Number of domains to analyze, default=200000")
                .addOption("p", "path", true, "Load path of the SQLite DB, default=cert.sqlite");
        final DefaultParser cliParser = new DefaultParser();
        final CommandLine cmdLine = cliParser.parse(options, args);
        final int NUM_FETCH = Integer.parseInt(cmdLine.getOptionValue("number", "200000"));
        final String DB_PATH = cmdLine.getOptionValue("path", "cert.sqlite");

        final Deque<String> domains = Util.readDomainList(NUM_FETCH);

        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (final Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
             final ProgressBar pb = new ProgressBarBuilder()
                     .setTaskName("Download")
                     .setUpdateIntervalMillis(500)
                     .setInitialMax(NUM_FETCH).build()) {
            String getDerOfDomainSt = "SELECT No, Der FROM Certs WHERE Domain = ?;";
            final PreparedStatement ps = conn.prepareStatement(getDerOfDomainSt);
            ps.setString(1, domains.poll());
            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                System.out.println(rs.getInt("No"));
                final byte[] der = rs.getBytes("Der");
                try (final ByteArrayInputStream byteInput = new ByteArrayInputStream(der)) {
                    final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(byteInput);
                    System.out.println(certificate.getIssuerDN());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
