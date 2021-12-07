package com.flyingblu.certAnalysis.utils;

import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.util.ArrayDeque;
import java.util.Deque;

public class Util {
    public static Deque<String> readDomainList(int length) {
        final Deque<String> domains = new ArrayDeque<>(length);
        try (final FileReader domainFile = new FileReader("top-1m.csv");
             final LineNumberReader lineReader = new LineNumberReader(domainFile)) {
            String read = lineReader.readLine();
            for (int i = 0; i < length && read != null; ++i) {
                final String[] strs = read.split(",");
                domains.add(strs[1]);
                read = lineReader.readLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return domains;
    }
}
