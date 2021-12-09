package com.flyingblu.certAnalysis.certAnalyzer;

import com.csvreader.CsvWriter;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.io.IOException;
import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.*;

public class AnalyzeCA {
    public static void main(String[] args) throws SQLException {
        final String DB_PATH = "cert.sqlite";
        final String FILE_PATH="./AnalyzeCA.csv";

        HashMap<String, Integer> issuer_count = new HashMap<>();
        for (var certs : new DBCertFetcher(DB_PATH)) {
            for(var cert : certs.certs){
                issuer_count.put(cert.getIssuerX500Principal().toString(), issuer_count.getOrDefault(cert.getIssuerX500Principal().toString(), 0)+1);
            }
        }
        HashMap<String, Integer> issuer_percent = new HashMap<>();
        for(Map.Entry<String, Integer> entry : issuer_count.entrySet()){
            if(entry.getValue() > 1000){
                issuer_percent.put(entry.getKey(), entry.getValue());
            }else{
                issuer_percent.put("others", issuer_percent.getOrDefault("others", 0)+entry.getValue());
            }
        }
        List<Map.Entry<String, Integer>> rank = new ArrayList<>(issuer_percent.entrySet());
        Collections.sort(rank, (o1, o2) -> (o2.getValue() - o1.getValue()));

        try {
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));
            String[] headers={"issuers","number"};
            csvWriter.writeRecord(headers);
            for(Map.Entry<String, Integer> t : rank){
                if (Objects.equals(t.getKey(), "others")) {
                    csvWriter.writeRecord(new String[] {t.getKey(), String.valueOf(t.getValue())});
                }else{
                    csvWriter.writeRecord(new String[] {t.getKey().split(",")[0].split("=")[1], String.valueOf(t.getValue())});
                }
            }
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
