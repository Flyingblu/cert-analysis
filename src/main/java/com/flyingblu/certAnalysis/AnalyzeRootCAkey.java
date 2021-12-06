package com.flyingblu.certAnalysis;


import com.csvreader.CsvWriter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;


public class AnalyzeRootCAkey {

    private  static final String FILE_PATH="./AnalyzeRootAuthorityKey.csv";
    private static final String DIR_PATH="./TrustedCA";


    public static void main(String[] args) throws CertificateException, IOException {
        File dir=new File(DIR_PATH);
        File[] files=dir.listFiles();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try{
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));
            String[] headers={"Authority","key_type","bit_count"};
            csvWriter.writeRecord(headers);
            for (File f: files){
                FileInputStream fis = new FileInputStream(f);
                Certificate c = cf.generateCertificate(fis);
                X509Certificate cert = (X509Certificate)c;
                fis.close();

                int end_of_name=f.getName().indexOf('.');
                String AuthorityName=f.getName().substring(0,end_of_name);

                String KeyContent=cert.getPublicKey().toString();
                int index_of_p=KeyContent.indexOf('p')-1;
                String key_type=KeyContent.substring(4,index_of_p);

                int bit_start=KeyContent.indexOf(',')+2;
                int bit_end=KeyContent.indexOf('t')-3;
                String bit_count=KeyContent.substring(bit_start,bit_end);

                List content=new ArrayList<String>();
                content.add(AuthorityName);
                content.add(key_type);
                content.add(bit_count);
                csvWriter.writeRecord((String[]) content.toArray(new String[0]));
            }
        }catch (Exception e){
            e.printStackTrace();
        }


    }
}
