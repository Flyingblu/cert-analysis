package com.flyingblu.certAnalysis;

import me.tongfei.progressbar.ProgressBar;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Deque;

public class FetchCertTask implements Runnable {

    private final ProgressBar pb;
    private final Deque<String> domains;
    private final Connection conn;
    private static final String insertStatement = "INSERT INTO Certs VALUES(?, ?, ?, ?);";
    private static final String insertErrStatement = "INSERT INTO CertErrs VALUES(?, ?, ?, ?);";
    private static final String countDomainStatement = "SELECT COUNT(*) FROM Certs WHERE Domain = ?;";
    private static final String countDomainErrStatement = "SELECT COUNT(*) FROM CertErrs WHERE Domain = ?;";

    public FetchCertTask(ProgressBar pb, Deque<String> domains, Connection conn) {
        this.pb = pb;
        this.domains = domains;
        this.conn = conn;
    }

    @Override
    public void run() {
        String domain;
        while (true) {
            synchronized (domains) {
                if (domains.isEmpty())
                    break;
                domain = domains.poll();
            }
            boolean exists = false;
            synchronized (conn) {
                try (final PreparedStatement st = conn.prepareStatement(countDomainStatement);
                     final PreparedStatement st1 = conn.prepareStatement(countDomainErrStatement)) {
                    st.setString(1, domain);
                    st1.setString(1, domain);
                    exists = st.executeQuery().getInt(1) >= 1
                            || st1.executeQuery().getInt(1) >= 1;
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (exists) {
                synchronized (pb) {
                    pb.step();
                }
                continue;
            }

            try {
                final X509Certificate[] certs = CertFetcher.getFromDomain(domain);

                synchronized (conn) {
                    for (int i = 0; i < certs.length; ++i) {
                        try (final PreparedStatement ps = conn.prepareStatement(insertStatement)) {
                            ps.setString(1, domain);
                            ps.setInt(2, i);
                            ps.setBytes(3, certs[i].getEncoded());
                            ps.setInt(4, certs.length);
                            ps.executeUpdate();
                        } catch (CertificateEncodingException | SQLException e) {
                            saveErr(domain, i, e.toString(), certs.length);
                            e.printStackTrace();
                        }
                        conn.commit();
                    }
                }
            } catch (IOException | SQLException e) {
                saveErr(domain, 0, e.toString(), 0);
            }
            synchronized (pb) {
                pb.step();
            }
        }
    }

    private void saveErr(String domain, int no, String err, int total) {
        synchronized (conn) {
            try (final PreparedStatement ps = conn.prepareStatement(insertErrStatement)) {
                ps.setString(1, domain);
                ps.setInt(2, no);
                ps.setString(3, err);
                ps.setInt(4, total);
                ps.executeUpdate();
                conn.commit();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}
