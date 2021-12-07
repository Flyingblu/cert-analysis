package com.flyingblu.certAnalysis.certAnalyzer;

import com.csvreader.CsvWriter;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class AnalyzeMisorderedChain {

    private static final String DB_PATH = "cert.sqlite";
    private static final String FILE_PATH="./AnalyzeMisorderedChain.csv";

    public static void main(String[] args) {
        try{
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));
            for (var certs : new DBCertFetcher(DB_PATH)) {
                if(certs.certs.length>0){
                    int index=0;
                    X509Certificate[] chain=certs.certs;
                    while(index<certs.certs.length-1){
                        if(!chain[index].getIssuerDN().equals(chain[index+1].getSubjectDN())){
                            String domain=certs.domain;
                            List content=new ArrayList<String>();
                            content.add(domain);
                            csvWriter.writeRecord((String[]) content.toArray(new String[0]));
                            break;
                        }else{
                            index++;
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
