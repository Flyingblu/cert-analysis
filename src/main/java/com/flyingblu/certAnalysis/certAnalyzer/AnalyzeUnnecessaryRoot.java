package com.flyingblu.certAnalysis.certAnalyzer;

import com.csvreader.CsvWriter;
import com.flyingblu.certAnalysis.cert.Cert;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class AnalyzeUnnecessaryRoot {

    private static final String DB_PATH = "cert.sqlite";
    private static final String FILE_PATH="./AnalyzeUnnecessaryRoot.csv";

    public static void main(String[] args)  {
        try{
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));

            for (var certs : new DBCertFetcher(DB_PATH)) {
                //exclude wrong cert and those self-signed
                if(certs.certs.length>1) {
                    for(var cert:certs.certs){
                        if(cert.getIssuerDN().equals(cert.getSubjectDN())){
                            String domain=certs.domain;

                            String[] IssuerInfo=cert.getIssuerDN().toString().split(",");
                            int index = IssuerInfo[0].indexOf('=');
                            String RootCA = IssuerInfo[0].substring(index+1,IssuerInfo[0].length());
                            List content=new ArrayList<String>();
                            content.add(domain);
                            content.add(RootCA);
                            csvWriter.writeRecord((String[]) content.toArray(new String[0]));
                        }
                    }
                }
            }
            csvWriter.close();
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }
}
