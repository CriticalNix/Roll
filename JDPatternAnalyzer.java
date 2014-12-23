/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jdpatternanalyzer;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
/**
 *
 * @author Conor
 */
public class JDPatternAnalyzer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Scanner input = new Scanner (System.in);
        System.out.println("Enter Encrypted server seed:");
        String serverHash = input.nextLine(); //takes entered server seed
        System.out.println("Enter Decrypted Server seed:");
        String serverSeed = input.nextLine();
        System.out.println("Enter Client Seed:");
        String clientSeed = input.nextLine();
        System.out.println("Enter # of roll to start"); // note, nonce always starts at 1; example Client seed: 000000000000000:1 <- Where 1 is always the initial nonce
        int rollStart = input.nextInt();
        System.out.println("Enter # of roll to end");
        int rollEnd = input.nextInt();
        System.out.println("Calculated rolls are as follows:");
        double[] arrayEmulatedRolls = new double[rollEnd];
        double[] arrayTrueRolls = new double[rollEnd];
        // Fill emulated rolls array
        for (int j=rollStart; j<= rollEnd ; j++) { 
        String currentClientSeed = clientSeed+":"+j;
        String HMAC512 = hmacDigest(currentClientSeed, serverHash, "HmacSHA512"); // we're on roll j.
        String[] hashArray = new String[26];  // create an array of all of the possible rolls for roll j.
        for (int i=0; i<=24; i++){
            hashArray[i] = HMAC512.substring((i*5), ((i*5)+5));
        }
        hashArray[25]= HMAC512.substring(125,128);  // to account for the possible outcome that we run out of 5 character breakdowns.
        // at this point we have 25 possibly array elements to test for less than 1million.
        // now we need to try to get a number less than 1,000,000 and divide it by 10,000
        int[] rollsLongIntArray = new int[26]; // 26 element integer array representing all of the possible rolls.
        for(int i=0; i<=25; i++){
            rollsLongIntArray[i] = convert(hashArray[i]);
        }
        //now we need to check array elements in order to try to find one less than 1million.
        // if we find one less than 1 million, we need to exit loop.
        
        boolean foundRoll = false;
        int counter = 0;
        double actualRoll = 0.00;
        while(foundRoll == false){
            if(rollsLongIntArray[counter] < 1000000){
                foundRoll = true;
                actualRoll = (double) rollsLongIntArray[counter] / 10000.00;
            } else {
                counter ++;
            }
        }
      arrayEmulatedRolls[j-1] = actualRoll;  
    }
       // fill trueRolls array!
        for (int j=rollStart; j<= rollEnd ; j++) { 
        String currentClientSeed = clientSeed+":"+j;
        String HMAC512 = hmacDigest(currentClientSeed, serverSeed, "HmacSHA512"); // we're on roll j.
        String[] hashArray = new String[26];  // create an array of all of the possible rolls for roll j.
        for (int i=0; i<=24; i++){
            hashArray[i] = HMAC512.substring((i*5), ((i*5)+5));
        }
        hashArray[25]= HMAC512.substring(125,128);  // to account for the possible outcome that we run out of 5 character breakdowns.
        // at this point we have 25 possibly array elements to test for less than 1million.
        // now we need to try to get a number less than 1,000,000 and divide it by 10,000
        int[] rollsLongIntArray = new int[26]; // 26 element integer array representing all of the possible rolls.
        for(int i=0; i<=25; i++){
            rollsLongIntArray[i] = convert(hashArray[i]);
        }
        //now we need to check array elements in order to try to find one less than 1million.
        // if we find one less than 1 million, we need to exit loop.
        
        boolean foundRoll = false;
        int counter = 0;
        double actualRoll = 0.00;
        while(foundRoll == false){
            if(rollsLongIntArray[counter] < 1000000){
                foundRoll = true;
                actualRoll = (double) rollsLongIntArray[counter] / 10000.00;
            } else {
                counter ++;
            }
        }
      arrayTrueRolls[j-1] = actualRoll;  
    }
        System.out.println("The same count was: " + (compare(arrayEmulatedRolls, arrayTrueRolls, rollStart, rollEnd)));
} 
    public static int compare(double[] arrayEmulatedRolls, double[] arrayTrueRolls, int rollStart, int rollEnd){
        int sameCount = 0;
        for(int i=rollStart; i<=rollEnd; i++){
            if(((arrayEmulatedRolls[i-1] <= 49.500) && (arrayTrueRolls[i-1] <= 49.500))||(((arrayEmulatedRolls[i-1] >= 50.4999) && (arrayTrueRolls[i-1] >= 50.4999))) ){
                sameCount++;
            }
        }
        
        
        return sameCount;
    }
        
    // String Hex to Integer decimal Module    
    public static int convert(String hex){ 
        Integer outputDecimal = Integer.parseInt(hex, 16);
        return outputDecimal;
    }
    
    //HMAC 512 encryption Module
    public static String hmacDigest(String msg, String keyString, String algo) {
    String digest = null;
    try {
      SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo);
      Mac mac = Mac.getInstance(algo);
      mac.init(key);

      byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));

      StringBuffer hash = new StringBuffer();
      for (int i = 0; i < bytes.length; i++) {
        String hex = Integer.toHexString(0xFF & bytes[i]);
        if (hex.length() == 1) {
          hash.append('0');
        }
        hash.append(hex);
      }
      digest = hash.toString();
    } catch (UnsupportedEncodingException e) {
    } catch (InvalidKeyException e) {
    } catch (NoSuchAlgorithmException e) {
    }
    return digest;
    }
}