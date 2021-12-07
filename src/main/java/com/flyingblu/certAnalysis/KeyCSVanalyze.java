package com.flyingblu.certAnalysis;

import com.csvreader.CsvReader;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class KeyCSVanalyze {

    private  static final String filePath="./AnalyzeKey.csv";

    /**
     *
     */
    private static void classifyKeyBit(){
        Set<String> RSAset=new HashSet<>();
        HashSet<String> ECset = new HashSet<>();
        String KeyBit;
        try {
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()){
                String key_type=csvReader.get("key_type");
                if (key_type.equals("EC")){
                    KeyBit=csvReader.get("bit_count");
                    if(!ECset.contains(KeyBit)) ECset.add(KeyBit);
                }else if(key_type.equals("RSA")){
                    KeyBit=csvReader.get("bit_count");
                    if(!RSAset.contains(KeyBit)) RSAset.add(KeyBit);
                }
            }
            System.out.println("RSA bit: "+RSAset.toString());
            System.out.println("EC bit: "+ECset.toString());
            System.out.println("=========================================");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     *
     */
    private static void CountKeyBit(){
        HashMap<String, Integer> RSAmap = new HashMap<>();
        HashMap<String, Integer> ECmap = new HashMap<>();

        RSAmap.put("1024",0);
        RSAmap.put("2024",0);
        RSAmap.put("2048",0);
        RSAmap.put("3072",0);
        RSAmap.put("3096",0);
        RSAmap.put("3112",0);
        RSAmap.put("4096",0);
        RSAmap.put("8192",0);

        ECmap.put("256",0);
        ECmap.put("384",0);

        String KeyBit;
        try{
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()){
                String key_type = csvReader.get("key_type");
                if(key_type.equals("RSA")){
                    KeyBit=csvReader.get("bit_count");
                    int counter=RSAmap.get(KeyBit)+1;
                    RSAmap.put(KeyBit,counter);
                }else if(key_type.equals("EC")){
                    KeyBit=csvReader.get("bit_count");
                    int counter=ECmap.get(KeyBit)+1;
                    ECmap.put(KeyBit,counter);
                }
            }
            System.out.println("RSA bit: "+RSAmap.toString());
            System.out.println("EC bit: "+ECmap.toString());
            System.out.println("=========================================");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        classifyKeyBit();
        CountKeyBit();

    }
}
