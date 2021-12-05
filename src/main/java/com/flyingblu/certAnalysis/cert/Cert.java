package com.flyingblu.certAnalysis.cert;

import java.security.cert.X509Certificate;

public class Cert {
    final public String domain;
    final public X509Certificate[] certs;

    @Override
    public String toString() {
        return "Cert{" +
                "domain='" + domain + '\'' +
                ", length='" + (certs != null ? certs.length : 0) + '\'' +
                '}';
    }


    public Cert(String domain, X509Certificate[] certs) {
        this.domain = domain;
        this.certs = certs;
    }
}
