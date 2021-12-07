package com.flyingblu.certAnalysis;

import com.csvreader.CsvWriter;
import com.flyingblu.certAnalysis.cert.DBCertFetcher;

import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class AnalyzeKey {

    private static final String DB_PATH = "cert.sqlite";
    private static final String FILE_PATH="./AnalyzeKey.csv";

    public static void main(String[] args) throws SQLException {

        try{
            CsvWriter csvWriter=new CsvWriter(FILE_PATH, ',', Charset.forName("GBK"));
            String[] headers={"domain","key_type","bit_count"};
            csvWriter.writeRecord(headers);
            for (var certs : new DBCertFetcher(DB_PATH)) {
                if(certs.certs.length>0){
                    String KeyContent=certs.certs[0].getPublicKey().toString();

                    String domain=certs.domain;

                    int index_of_p=KeyContent.indexOf('p');
                    String key_type=KeyContent.substring(4,index_of_p-1);

                    int bit_start=KeyContent.indexOf(',')+2;
                    int bit_end=KeyContent.indexOf('t')-3;
                    String bit_count=KeyContent.substring(bit_start,bit_end);

                    List content=new ArrayList<String>();
                    content.add(domain);
                    content.add(key_type);
                    content.add(bit_count);
                    csvWriter.writeRecord((String[]) content.toArray(new String[0]));
                }
            }
        }catch (Exception e ){
            e.printStackTrace();
        }

    }
}
