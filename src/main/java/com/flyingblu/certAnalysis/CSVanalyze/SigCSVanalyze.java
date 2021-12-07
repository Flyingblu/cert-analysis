package com.flyingblu.certAnalysis.CSVanalyze;

import com.csvreader.CsvReader;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;

public class SigCSVanalyze {

    private static final String filePath="./AnalyzeSig.csv";
    private static HashSet<String> algorithmSet = new HashSet<>();

    /**
     *
     */
    private static void classifyAlgorithm(){
        try{
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()) {
                String algorithm=csvReader.get("algorithm");
                if (!algorithmSet.contains(algorithm)) algorithmSet.add(algorithm);
            }
            System.out.println("algorithm type: "+algorithmSet.toString());
            System.out.println("=========================================");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static void countAlgorithm(){
        HashMap<String, Integer> algorithmMap = new HashMap<>();
        for (String algorithm:algorithmSet){
            algorithmMap.put(algorithm,0);
        }
        try {
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()){
                String algorithm=csvReader.get("algorithm");
                int counter=algorithmMap.get(algorithm)+1;
                algorithmMap.put(algorithm,counter);
            }
            System.out.println("algorithm statistics: "+algorithmMap.toString());
            System.out.println("=========================================");
            csvReader.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        classifyAlgorithm();
        countAlgorithm();
    }
}
