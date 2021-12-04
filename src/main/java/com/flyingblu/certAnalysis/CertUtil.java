package com.flyingblu.certAnalysis;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

public class CertUtil {

    static final String getDerOfDomainSt = "SELECT No, Der FROM Certs WHERE Domain = ?;";
    static final CertificateFactory certFactory;

    static {
        CertificateFactory tmpCF;
        try {
            tmpCF = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
            tmpCF = null;
        }
        certFactory = tmpCF;
    }

    private static final TrustManager[] trustManagers = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
            }};


    public static X509Certificate[] getCertChainFromDomain(String domainName) throws IOException {
        // Disable all cert check, just download it
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustManagers, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        URL url = new URL("https://" + domainName);
        final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.connect();
        final Certificate[] certs = conn.getServerCertificates();
        return (X509Certificate[]) certs;
    }

    public static X509Certificate[] getCertChainFromDB(String domainName, Connection conn) throws SQLException, CertificateException {
        final PreparedStatement ps = conn.prepareStatement(getDerOfDomainSt);
        ps.setString(1, domainName);
        final ResultSet rs = ps.executeQuery();
        final ArrayList<X509Certificate> certs = new ArrayList<>();
        while (rs.next()) {
            System.out.println(rs.getInt("No"));
            final byte[] der = rs.getBytes("Der");
            try (final ByteArrayInputStream byteInput = new ByteArrayInputStream(der)) {
                certs.add((X509Certificate) certFactory.generateCertificate(byteInput));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return (X509Certificate[]) certs.toArray();
    }
}
