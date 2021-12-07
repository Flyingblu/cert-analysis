package com.flyingblu.certAnalysis.cert;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.*;

public class CertRevocationChecker {
    private Map<String, X509CRL> crlCache = new HashMap<>();
    private final CertificateFactory cf = CertificateFactory.getInstance("X.509");

    public CertRevocationChecker() throws CertificateException {
    }

    public static List<String> getCRLURI(X509Certificate cert) throws IOException {
        final var crlURI = new ArrayList<String>();
        final var crl = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crl != null) {
            ASN1Sequence asn1Seq = (ASN1Sequence) JcaX509ExtensionUtils.parseExtensionValue(crl);
            final CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Seq);

            for (var point : distPoint.getDistributionPoints()) {
                final var pointName = point.getDistributionPoint();
                if (pointName != null && pointName.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(pointName.getName()).getNames();
                    for (var genName : genNames) {
                        if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(genName.getName()).getString().trim();
                            crlURI.add(url);
                        }
                    }
                }
            }
        }
        return crlURI;
    }

    public static String getOCSPURI(X509Certificate cert) throws IOException {
        String ocspURI = null;
        final byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia != null) {
            // Parse the ASN.1 sequence to get OCSP URI
            ASN1Sequence asn1Seq = (ASN1Sequence) JcaX509ExtensionUtils.parseExtensionValue(aia); // AuthorityInfoAccessSyntax
            Enumeration<?> objects = asn1Seq.getObjects();

            while (objects.hasMoreElements()) {
                ASN1Sequence obj = (ASN1Sequence) objects.nextElement(); // AccessDescription
                var oid = obj.getObjectAt(0); // accessMethod
                if (oid.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                    ASN1TaggedObject location = (ASN1TaggedObject) obj.getObjectAt(1); // accessLocation
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        DEROctetString uri = (DEROctetString) location.getBaseObject();
                        ocspURI = new String(uri.getOctets());
                    }
                }
            }
        }
        return ocspURI;
    }

    public boolean checkCRLRevocation(List<String> crlURI, X509Certificate cert) throws IOException, CRLException {
        for (String crlUrl : crlURI) {
            var crl = crlCache.get(crlUrl);
            if (crl == null) {
                crl = downloadCRL(crlUrl);
                crlCache.put(crlUrl, crl);
            }
            if (crl != null && crl.isRevoked(cert))
                return true;
        }
        return false;
    }

    private X509CRL downloadCRL(String crlURL)
            throws IOException, CRLException {
        try (final var crlStream = new URL(crlURL).openStream()) {
            return (X509CRL) cf.generateCRL(crlStream);
        } catch (Exception e) {
            return null;
        }
    }
}
