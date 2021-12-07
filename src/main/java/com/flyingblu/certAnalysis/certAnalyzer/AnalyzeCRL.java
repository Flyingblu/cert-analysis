package com.flyingblu.certAnalysis;

import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.sql.*;
import java.util.HashMap;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;




public class AnalyzeCRL {
    public static void main(String[] args) throws SQLException, IOException {
        final String DB_PATH = "cert.sqlite";

        // Sample task. Copy and paste this file to create your own.
        final var version = new HashMap<String, Integer>();
        int noCRLCount = 0;
        List<String> crlUrls = new ArrayList<String>();
        for (var certs : new DBCertFetcher(DB_PATH)) {

            for (var cert : certs.certs) {

                byte[] crlDistributionPointDerEncodedArray = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
                if(crlDistributionPointDerEncodedArray != null)
                {
                    ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointDerEncodedArray));
                    ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
                    DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;

                    oAsnInStream.close();

                    byte[] crldpExtOctets = dosCrlDP.getOctets();
                    ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
                    ASN1Primitive derObj2 = oAsnInStream2.readObject();
                    CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

                    oAsnInStream2.close();
                    for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                        DistributionPointName dpn = dp.getDistributionPoint();
                        // Look for URIs in fullName
                        if (dpn != null) {
                            if (dpn.getType() == DistributionPointName.FULL_NAME) {
                                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                                // Look for an URI
                                for (int j = 0; j < genNames.length; j++) {
                                    if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                                        String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                                        crlUrls.add(url);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    ++noCRLCount;
                }
            }
        }

        for (String url : crlUrls)
            System.out.println(url);
        System.out.println("The number of URL without CRL is ");
        System.out.println(noCRLCount);
    }
}
