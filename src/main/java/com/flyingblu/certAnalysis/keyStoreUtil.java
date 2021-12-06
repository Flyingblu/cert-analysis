package com.flyingblu.certAnalysis;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;

public class keyStoreUtil {
    public static void createKeyStoreFromDir(String certDir, String saveName, String passwd) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            // create empty KeyStore
            ks.load(null, passwd.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        final var failedFiles = new ArrayList<String>();
        int countSucc = 0;
        for (File certFile : new File(certDir).listFiles()) {
            try (final var certIS = new FileInputStream(certFile)) {
                final String certFileName = certFile.getName();
                // Get rid of the file extension
                final String certName = certFileName.substring(0, certFileName.lastIndexOf("."));
                final var cert = cf.generateCertificate(certIS);
                ks.setCertificateEntry(certName, cert);
                ++countSucc;
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                failedFiles.add(certFile.getPath());
            }
        }
        if (failedFiles.size() != 0)
            System.out.println("Failed to generate certificate for files:\n" + failedFiles);
        System.out.println(ks.size() + " certificates imported");

        try (final FileOutputStream fos = new FileOutputStream(saveName)) {
            ks.store(fos, passwd.toCharArray());
        }
    }
}
