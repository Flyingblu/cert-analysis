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
//        int total_certificate = 0;
        HashMap<String, Integer> issuer_count = new HashMap<>();
        int total = 0;
        for (var certs : new DBCertFetcher(DB_PATH)) {
            for(var cert : certs.certs){
                total++;
                String organization = " ";
                if(cert.getIssuerX500Principal().toString().split("O=").length > 1){
                    organization = cert.getIssuerX500Principal().toString().split("O=")[1].split(",")[0].replace("\"", "");
                }else{
                    organization = cert.getIssuerX500Principal().toString().split("CN=")[1];
                }
                if(organization.toLowerCase().contains("daddy")){
                    organization = "GoDaddy";
                }
                if(organization.toLowerCase().contains("digital signature trust")){
                    organization = "IdenTrust";
                }
                if(organization.toLowerCase().contains("globalsign")){
                    organization = "GlobalSign";
                }
                if(organization.toLowerCase().contains("internet security")){
                    organization = "Let's Encrypt";
                }
                if(organization.toLowerCase().contains("baltimore")){
                    organization = "DigiCert Inc";
                }
                if(organization.toLowerCase().contains("comodo")){
                    organization = "Comodo CA Limited";
                }
                if(organization.toLowerCase().contains("unizeto")){
                    organization = "Unizeto";
                }
                issuer_count.put(organization, issuer_count.getOrDefault(organization, 0)+1);
//                issuer_count.put(cert.getIssuerX500Principal().toString(), issuer_count.getOrDefault(cert.getIssuerX500Principal().toString(), 0)+1);
            }
        }
        System.out.println(total);
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
            String[] headers={"Rank", "issuer","number", "percentage"};
            csvWriter.writeRecord(headers);
            int count = 1;
            for(Map.Entry<String, Integer> t : rank){
                csvWriter.writeRecord(new String[] {String.valueOf(count), t.getKey(), String.valueOf(t.getValue()), String.format("%.2f", (double)t.getValue()/total*100) + "%"});
//                if (Objects.equals(t.getKey(), "others")) {
//                    csvWriter.writeRecord(new String[] {t.getKey(), String.valueOf(t.getValue())});
//                }else{
////                    csvWriter.writeRecord(new String[] {t.getKey().split(",")[0].split("=")[1], String.valueOf(t.getValue())});
//                }
                count++;
            }
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
