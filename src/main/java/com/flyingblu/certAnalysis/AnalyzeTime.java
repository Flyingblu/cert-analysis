package com.flyingblu.certAnalysis;

import com.csvreader.CsvWriter;
import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.*;

public class AnalyzeTime {
    public static void main(String[] args) throws ParseException, SQLException, CertificateException {
        final Options options = new Options();
        options.addOption("n", "number", true, "Number of domains to analyze, default=200000")
                .addOption("p", "path", true, "Load path of the SQLite DB, default=cert.sqlite");
        final DefaultParser cliParser = new DefaultParser();
        final CommandLine cmdLine = cliParser.parse(options, args);
        final int NUM_FETCH = Integer.parseInt(cmdLine.getOptionValue("number", "200000"));
        final String DB_PATH = cmdLine.getOptionValue("path", "cert.sqlite");

        final Deque<String> domains = Util.readDomainList(NUM_FETCH);

        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (final Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
             final ProgressBar pb = new ProgressBarBuilder()
                     .setTaskName("Analyze")
                     .setUpdateIntervalMillis(500)
                     .setInitialMax(NUM_FETCH).build()) {

            String FilePath="./AnalyzeTime.csv";
            CsvWriter csvWriter=new CsvWriter(FilePath, ',', Charset.forName("GBK"));
            try {

                String[] headers = {"domain","StartTime","EndTime","ValidTime"};
                csvWriter.writeRecord(headers);

                Iterator iterator=domains.iterator();
                for (var domain:domains){
                    var certs=CertUtil.getCertChainFromDB(domain,conn);
                    if(certs.length!=0){

                        Date StartTime = certs[0].getNotBefore();
                        Date EndTime = certs[0].getNotAfter();
                        long validTime = (EndTime.getTime()- StartTime.getTime())/(24*60*60*1000);

                        List content=new ArrayList<String>();
                        content.add(domain);
                        content.add(StartTime.toString());
                        content.add(EndTime.toString());
                        content.add(String.valueOf(validTime));
                        csvWriter.writeRecord((String[]) content.toArray(new String[0]));
                        pb.step();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                csvWriter.close();
            }
        }
    }
}
