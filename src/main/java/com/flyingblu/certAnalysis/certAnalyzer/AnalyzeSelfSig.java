package com.flyingblu.certAnalysis.certAnalyzer;

import com.csvreader.CsvWriter;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.*;

public class AnalyzeSelfSig {
    public static void main(String[] args) throws SQLException {
        final String DB_PATH = "cert.sqlite";
        final String FILE_PATH="./AnalyzeSelfSig.csv";

        // check if self-signed
        int count_self = 0;
        int count_total = 0;

        for (var certs : new DBCertFetcher(DB_PATH)) {
            count_total++;
            if(certs.certs[0].getSubjectX500Principal().equals(certs.certs[0].getIssuerX500Principal())){
                count_self++;
            }

        }
        System.out.println("number of self-signed domain: " + count_self);
        System.out.println("number of total domain: " + count_total);

        try {
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));
            csvWriter.writeRecord(new String[]{"number of self-signed domain", String.valueOf(count_self)});
            csvWriter.writeRecord(new String[]{"number of total domain", String.valueOf(count_total)});
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
