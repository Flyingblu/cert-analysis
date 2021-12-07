package com.flyingblu.certAnalysis.cert;

import com.flyingblu.certAnalysis.utils.CertUtil;
import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class DBCertFetcher implements Iterable<Cert> {
    final private String[] domains;
    final private Connection conn;

    final private class CertIterator implements Iterator<Cert> {
        private int position = 0;
        final private ProgressBar pb;

        private CertIterator() {
            pb = new ProgressBarBuilder()
                    .setTaskName("Analyze")
                    .setUpdateIntervalMillis(500)
                    .setInitialMax(domains.length).build();
        }

        @Override
        public boolean hasNext() {
            return position < domains.length;
        }

        @Override
        public Cert next() {
            if (!hasNext())
                throw new NoSuchElementException();
            try {
                pb.step();
                if (position == domains.length - 1)
                    pb.close();
                return getCertChainForDomain(domains[position++]);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
    }


    public DBCertFetcher(String dbPath) throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        domains = CertUtil.getDomainListFromDB(conn);
    }

    public DBCertFetcher(String dbPath, String trustDomainPath) throws SQLException, IOException {
        conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        final var domains = new ArrayList<String>();
        try (final var domainReader = new LineNumberReader(new FileReader(trustDomainPath))) {
            domainReader.lines().forEach(domains::add);
        }
        this.domains = domains.toArray(String[]::new);
    }


    @Override
    public Iterator<Cert> iterator() {
        return new CertIterator();
    }

    public final Cert getCertChainForDomain(String domain) throws SQLException, CertificateException {
        final X509Certificate[] certs = CertUtil.getCertChainFromDB(domain, conn);
        return new Cert(domain, certs);
    }
}
