package com.flyingblu.certAnalysis.CSVanalyze;

import com.csvreader.CsvReader;

import java.io.FileNotFoundException;
import java.io.IOException;

public class TimeCSVanalyze {
    private  static final String filePath="./AnalyzeTime.csv";
    private  static int TotalRecord;

    private  static int LessThan90Days=0;
    private  static int Between90and365Days=0;
    private  static int Between365and730Days=0;
    private  static int Between730and1095Days=0;
    private  static int MoreThan1095Days=0;

    /**
     *
     * @param
     */
    private static void countRecord(){
        int recordCounter=0;
        try{
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()) recordCounter++;
            TotalRecord=recordCounter;
            System.out.println("total record is: "+TotalRecord);
            System.out.println("============================");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     * @param
     */
    private static void classifyValidTime(){
        double percentage;
        try{
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()){
                int validTime = Integer.parseInt(csvReader.get("ValidTime"));
                if(validTime<=90) LessThan90Days++;
                else if(validTime>90&&validTime<=365) Between90and365Days++;
                else if(validTime>365&&validTime<=730) Between365and730Days++;
                else if(validTime>730&&validTime<=1095) Between730and1095Days++;
                else MoreThan1095Days++;
            }
            System.out.println(LessThan90Days+" less than 90");
            percentage=(double) LessThan90Days/(double) TotalRecord*100;
            System.out.println("percentage is "+percentage+"%");
            System.out.println("============================");

            System.out.println(Between90and365Days+" between 90 and 365");
            percentage=(double) Between90and365Days/(double) TotalRecord*100;
            System.out.println("percentage is "+percentage+"%");
            System.out.println("============================");

            System.out.println(Between365and730Days+" lbetween 365 and 730");
            percentage=(double) Between365and730Days/(double) TotalRecord*100;
            System.out.println("percentage is "+percentage+"%");
            System.out.println("============================");

            System.out.println(Between730and1095Days+" between 730 and 1095");
            percentage=(double) Between730and1095Days/(double) TotalRecord*100;
            System.out.println("percentage is "+percentage+"%");
            System.out.println("============================");

            System.out.println(MoreThan1095Days+" more than 1095");
            percentage=(double) MoreThan1095Days/(double) TotalRecord*100;
            System.out.println("percentage is "+percentage+"%");
            System.out.println("============================");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
     */
    private static  void ExpireCert(){
        int ExpireCounter=0;
        try{
            CsvReader csvReader = new CsvReader(filePath);
            csvReader.readHeaders();
            while (csvReader.readRecord()){
                String isValid=csvReader.get("isValid");
                if(!isValid.equals("True")) ExpireCounter++;
            }
            System.out.println(ExpireCounter+" certs are expired");
            System.out.println("percentage is "+((double)ExpireCounter/(double)TotalRecord*100)+"%");
            System.out.println("============================");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
            countRecord();
            classifyValidTime();
            ExpireCert();
    }
}
