package com.diegocueva.cryptolib;


import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 *
 * @author dcueva
 */
public class UCripto {    
    
    public static final char[] C_DICC = "bcdfjklmnprsty".toCharArray();
    public static final char[] V_DICC = "aeiou".toCharArray();
    public static final int    CYCLES_DESEDE =  13;
    public static final int    CYCLES_HASH   = 100;
    public static final int    WORDS_AMOUNT  =  12;
    public static final String CHARSET_NAME  = "UTF-8";
    
    public static KeyPair buildKeyPair(String seed) throws Exception{       
        SecureRandom ss = new SecureRandom(seed.getBytes(CHARSET_NAME));
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512, ss);
        KeyPair myKeyPair = keyGen.genKeyPair();
        return myKeyPair;
    }
    
    public static byte[] encrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static String encrypt(String strData, Key key) throws Exception {
        return Base64.getEncoder().encodeToString(encrypt(strData.getBytes(CHARSET_NAME), key));
    }
    
    public static String decrypt(String strData, Key key) throws Exception {
        byte[] data = Base64.getDecoder().decode(strData);        
        return new String(decrypt(data, key), CHARSET_NAME);
    }
    
    public static String buildWord(SecureRandom secureRandom){
        StringBuilder word = new StringBuilder();
        
        for(int i=0; i<4; i++){
            word.append(C_DICC[secureRandom.nextInt(C_DICC.length)]);
            word.append(V_DICC[secureRandom.nextInt(V_DICC.length)]);
        }
        
        return word.toString();
    }
    
    public static List<String> getWords()throws Exception{
        SecureRandom random = new SecureRandom(Long.toString(System.currentTimeMillis(), 16).getBytes(CHARSET_NAME));
        List<String> words = new ArrayList<>();
        
        for(int i=0; i<WORDS_AMOUNT; i++){
            words.add(buildWord(random));
        }
        
        return words;
    }
    
    public static byte[] hashIt(byte[] data, int times) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            for(int i=0; i<times;i++){
                digest.update(data, 0, data.length);
                data = digest.digest();
            }
            return data;
        } catch (Exception e) {
            // Log.error("", e);
            return e.toString().getBytes();
        }        
    }
    
    public static String hashIt(String texto) {
        try {
            return Base64.getEncoder().encodeToString(hashIt(texto.getBytes(CHARSET_NAME), CYCLES_HASH));
        } catch (UnsupportedEncodingException e) {
            // Log.error("", e);
            return e.toString();
        }
    }
    
    public static String shiftString(String string){
        return string.charAt(string.length() - 1) + string.substring(0, string.length() - 1);
    }
    
    private static List<String> bulidListShifts(String string, int size){
        List<String> list = new ArrayList<>(size);
        for(int i=0; i<size; i++){
            list.add(shiftString(string));
        }
        return list;
    }

    public static SecretKey buildDESedeKey(byte[] keyBytes)throws Exception{
        KeySpec          keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory secretKeyFactory =  SecretKeyFactory.getInstance("DESede");        
        return secretKeyFactory.generateSecret(keySpec);
    }
    
    public static byte[] encryptDESede(byte[] data, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return  cipher.doFinal(data);
    }
    
    public static byte[] decryptDESede(byte[] data, SecretKey key) throws Exception{
        Cipher cipher = Cipher.getInstance("DESede");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return  cipher.doFinal(data);
    }
    
    public static String encryptStrongDESede(String dataStr, String keyBase) {
        if(keyBase.length() >= 24){
            try{
                byte[] data = dataStr.getBytes(CHARSET_NAME);
                List<String> keys = bulidListShifts(keyBase, CYCLES_DESEDE);
                for(int i=0; i<CYCLES_DESEDE; i++){
                    data = encryptDESede(data, buildDESedeKey(keys.get(i).getBytes(CHARSET_NAME)));
                }
                return Base64.getEncoder().encodeToString(data);                
            }catch(Exception e){
                throw new IllegalStateException("UCripto_e never mind", e);
            }
        }
        throw new IllegalArgumentException("Size actual "+keyBase.length()+ " expected 24");
    }
    
    public static String decryptStrongDESede(String dataStr, String keyBase) {
        if(keyBase.length() >= 24){
            try{
                byte[] data = Base64.getDecoder().decode(dataStr);
                List<String> keys = bulidListShifts(keyBase, CYCLES_DESEDE);
                Collections.reverse(keys);
                for(int i=0; i<CYCLES_DESEDE; i++){
                    data = decryptDESede(data, buildDESedeKey(keys.get(i).getBytes(CHARSET_NAME)));
                }
                return new String(data, CHARSET_NAME);
            }catch(Exception e){
                throw new IllegalStateException("UCripto_d never mind", e);
            }
        }
        throw new IllegalArgumentException("Size actual "+keyBase.length()+ " expected 24");        
    }
    
    public static List<String> mixIt(List<String> words){
        List<String> mixed = new ArrayList<>();
        words.forEach(wordA->{
            List<String> sec = new ArrayList<>(words);
            sec.remove(wordA);
            sec.forEach(wordB->mixed.add(wordA+wordB));
        });
        return mixed;
    }
    
    public static List<String> packData(String data, String password, List<String> words) {
        String passwordHash = hashIt(password);
        List<String> packageLines = new ArrayList<>();
        packageLines.add(encryptStrongDESede(data, passwordHash));
        mixIt(words).forEach(twoWords->
                packageLines.add(encryptStrongDESede(password, hashIt(twoWords)))
        );
        return packageLines;
    }
    
    public static String unpackDataUsingPassword(String lineFromPasswordHash, String password) {
        return decryptStrongDESede(lineFromPasswordHash, hashIt(password));
    }
    
    public static String unpackDataUsingWords(String packedData, String lineFromTwoWords, String wordA, String wordB) {
        String password = decryptStrongDESede(lineFromTwoWords, hashIt(wordA+wordB));
        return unpackDataUsingPassword(packedData, password);
    }
    
    public static void validateWords(List<String> lines, List<String> words) {
        AtomicInteger i = new AtomicInteger(0);
        words.forEach(wordA->{
            List<String> sec = new ArrayList<>(words);
            sec.remove(wordA);
            sec.forEach(wordB->{
                try{
                    decryptStrongDESede(lines.get(i.incrementAndGet()), hashIt(wordA+wordB));
                }catch(Exception e){
                    throw new IllegalArgumentException("Words '"+wordA + "' and '"+wordB+"' are incorrect");
                }
            });
        });        
    }            

}
