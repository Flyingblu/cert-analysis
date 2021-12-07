package com.flyingblu.certAnalysis.certAnalyzer;

import com.csvreader.CsvWriter;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class AnalyzeSignature {

    private static final String DB_PATH = "cert.sqlite";
    private static final String FILE_PATH="./AnalyzeSig.csv";

    public static void main(String[] args) {
        try {
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));
            String[] headers={"domain","algorithm"};
            csvWriter.writeRecord(headers);
            for (var certs : new DBCertFetcher(DB_PATH)) {
                if (certs.certs.length>0){
                    String domain=certs.domain;
                    String algorithm=certs.certs[0].getSigAlgName();

                    List content=new ArrayList<String>();
                    content.add(domain);
                    content.add(algorithm);
                    csvWriter.writeRecord((String[]) content.toArray(new String[0]));
                }
            }
            csvWriter.close();
        } catch (IOException | SQLException e) {
            e.printStackTrace();
        }
    }
}
