package com.flyingblu.certAnalysis;

import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.Deque;

public class FetchCert {
    public static void main(String[] args) throws ParseException {
        final Options options = new Options();
        options.addOption("t", "thread", true, "Number of downloading threads, default=10")
                .addOption("n", "number", true, "Number of domains to fetch, default=200000")
                .addOption("p", "path", true, "Save path of the SQLite DB, default=cert.sqlite");
        final DefaultParser cliParser = new DefaultParser();
        final CommandLine cmdLine = cliParser.parse(options, args);
        final int NUM_FETCH = Integer.parseInt(cmdLine.getOptionValue("number", "200000"));
        final int NUM_THREADS = Integer.parseInt(cmdLine.getOptionValue("thread", "10"));
        final String DB_PATH = cmdLine.getOptionValue("path", "cert.sqlite");

        final Deque<String> domains = new ArrayDeque<>(NUM_FETCH);
        try (final FileReader domainFile = new FileReader("top-1m.csv");
             final LineNumberReader lineReader = new LineNumberReader(domainFile)) {
            String read = "";
            for (int i = 0; i < NUM_FETCH && read != null; ++i) {
                read = lineReader.readLine();
                final String[] strs = read.split(",");
                domains.add(strs[1]);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (final Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
             final ProgressBar pb = new ProgressBarBuilder()
                     .setTaskName("Download")
                     .setUpdateIntervalMillis(500)
                     .setInitialMax(NUM_FETCH).build()) {

            // Create tables
            String createCertTable = "CREATE TABLE IF NOT EXISTS Certs (\n" +
                    "    Domain      VARCHAR(100),\n" +
                    "    No          INTEGER,\n" +
                    "    Der         BLOB,\n" +
                    "    Total       INTEGER\n," +
                    "    PRIMARY KEY (Domain, No)\n" +
                    ")";
            String createErrTable = "CREATE TABLE IF NOT EXISTS CertErrs\n" +
                    "(\n" +
                    "    domain VARCHAR(100),\n" +
                    "    No     INTEGER,\n" +
                    "    Err    TEXT,\n" +
                    "    Total  INTEGER,\n" +
                    "    PRIMARY KEY (domain, No)\n" +
                    ");";

            conn.setAutoCommit(false);
            conn.createStatement().execute(createCertTable);
            conn.createStatement().execute(createErrTable);
            conn.commit();


            final Thread[] threads = new Thread[NUM_THREADS];
            for (int i = 0; i < NUM_THREADS; ++i) {
                threads[i] = new Thread(new FetchCertTask(pb, domains, conn));
                threads[i].start();
            }
            for (var thread : threads) {
                thread.join();
            }
        } catch (InterruptedException | SQLException e) {
            e.printStackTrace();
        }
    }
}
