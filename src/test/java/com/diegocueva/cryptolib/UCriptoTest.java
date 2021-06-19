package com.diegocueva.cryptolib;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

/**
 *
 * @author dcueva
 */
public class UCriptoTest {
    
    public static final String STRING_BASE = "d_cueva@hotmail.com";
    public static final String HASH_BASE   = "Información sensible, claves, números de cuenta, fechas, transacciones";
    public static final String USER_WORDS  = "siculolulifepotebujibobulicocusapapitulekikubebunuyirepinoradojajarorisiyoruyayineketimeputetipi";
    
    public UCriptoTest() {
    }
    
    @Test
    public void providersTest()throws Exception{
        Provider [] providerList = Security.getProviders();
        System.out.println("---------------------Security.getProviders-----------------------------");
        System.out.println("SSL provider=" + SSLContext.getDefault().getProvider());
        
        Arrays.asList(providerList).forEach(prv->{
            System.out.println("\tname="+prv.getName()+" info="+prv.getInfo() );
        });
    }
    
    @Test
    public void secureRandomTest()throws Exception{
        System.out.println("--------------------- secureRamdom ---------------------");
        
        final Set<String> algorithms = Security.getAlgorithms("SecureRandom");

        algorithms.forEach((algorithm) -> {
            System.out.println(algorithm);
        });

        final String defaultAlgorithm = new SecureRandom().getAlgorithm();        

        System.out.println("default: " + defaultAlgorithm);        
        SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG", "SUN");
        sr1.setSeed(USER_WORDS.getBytes(UCripto.CHARSET_NAME));

        SecureRandom sr2 = SecureRandom.getInstance("SHA1PRNG", "SUN");
        sr2.setSeed(USER_WORDS.getBytes(UCripto.CHARSET_NAME));

        System.out.println("sr1 = "+sr1.getProvider());
        System.out.println("sr1 = "+sr1.nextLong());
        System.out.println("sr2 = "+sr2.getProvider());
        System.out.println("sr2 = "+sr2.nextLong());
    }
    
    @Test
    public void hashTest() throws Exception {
        System.out.println("---------------------hashTest-----------------------------");
        System.out.println(UCripto.hashIt("root98"));
        System.out.println(UCripto.hashIt("1234"));
        System.out.println(UCripto.hashIt(USER_WORDS));
    }
    
    @Test
    public void buildWordTest() throws Exception {
        SecureRandom random = new SecureRandom(Long.toString(System.currentTimeMillis(), 16).getBytes(UCripto.CHARSET_NAME));
        System.out.println("---------------------WORDS-----------------------------");
        for(int i=0;i<12;i++){
            String word = UCripto.buildWord(random);
            System.out.println("\t"+(i+1)+". "+word);
        }
    }
    
    @Test
    public void ECDSATest()throws Exception{
        System.out.println("-----------------------------ECDSATest-----------------------------");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        
        SecureRandom ss = new SecureRandom(USER_WORDS.getBytes(UCripto.CHARSET_NAME));
        keyGen.initialize(ecSpec, ss);
        
        KeyPair kp = keyGen.generateKeyPair();
        PublicKey pub = kp.getPublic();
        PrivateKey pvt = kp.getPrivate();
        
        ECPrivateKey epvt = (ECPrivateKey)pvt;
        String privateKey = epvt.getS().toString(16).toUpperCase();
        System.out.println("private="+privateKey);
        
        ECPublicKey epub = (ECPublicKey)pub;
        ECPoint pt = epub.getW();
        String sx = pt.getAffineX().toString(16).toUpperCase();
        String sy = pt.getAffineY().toString(16).toUpperCase();
        String bcPub = "04" + sx + sy;
        System.out.println("public=" + bcPub);
        
        Assertions.assertEquals("63DC5E30DD45CBE01A6D916AB079B4E80D8905C55478FC6DD60314CFC55B966", privateKey);
        Assertions.assertEquals("043805E0E64482C5EC30319AFDDCD3D3A07DC5EBC49FC20E2F4B69A390C536523419746C6B79F067F7DD226238693D2822C2DD1C2637C4E1918FC66BDD95BFE84", bcPub);
    }
    
    @Test
    public void genKeyPairTest() throws Exception {
        String seed = USER_WORDS;
        
        System.out.println("--------------------- Gen Key Pair ----------------------------");
        KeyPair keyPairA = UCripto.buildKeyPair(seed);
        System.out.println("PvtK A:\n"+keyPairA.getPrivate().getClass().getName()+"\n"+keyPairA.getPrivate().toString());
        System.out.println("PubK A:\n"+keyPairA.getPublic().getClass().getName()+"\n"+keyPairA.getPublic().toString());
        RSAPrivateCrtKeyImpl rsaPvtA = (RSAPrivateCrtKeyImpl)keyPairA.getPrivate();
        RSAPublicKeyImpl     rsaPubA = (RSAPublicKeyImpl)keyPairA.getPublic();
        System.out.println("\tPUB Str="+rsaPubA.getModulus().toString(16).toUpperCase());
        System.out.println("--------------------------------------");
        
        KeyPair keyPairB = UCripto.buildKeyPair(seed);
        System.out.println("PvtK B:\n"+keyPairB.getPrivate().toString());
        System.out.println("PubK B:\n"+keyPairB.getPublic().toString());
        RSAPrivateCrtKeyImpl rsaPvtB = (RSAPrivateCrtKeyImpl)keyPairB.getPrivate();
        RSAPublicKeyImpl     rsaPubB = (RSAPublicKeyImpl)keyPairB.getPublic();
        System.out.println("\tPUB Str="+rsaPubB.getModulus().toString(16).toUpperCase());
        System.out.println("--------------------------------------");
        
        // Error : cuando el provider es SunRsaSign RSA private CRT key
        // Se generan diferentes KeyPair con la misma seed random
        String enc1 = UCripto.encrypt(STRING_BASE, keyPairA.getPrivate());
        String dec1 = UCripto.decrypt(enc1,  keyPairA.getPublic());
        
        String enc2 = UCripto.encrypt(STRING_BASE, keyPairB.getPrivate());
        String dec2 = UCripto.decrypt(enc2,  keyPairB.getPublic());
        
        System.out.println("enc1="+enc1);
        System.out.println("dec1="+dec1);
        
        System.out.println("enc2="+enc2);
        System.out.println("dec2="+dec2);
        
        Assertions.assertEquals(STRING_BASE, dec1);
        Assertions.assertEquals(STRING_BASE, dec2);
        // Assertions.assertEquals(enc1, enc2);
    }
    
    @Test
    public void shiftTest() throws Exception {
        String string  = "1234567890";
        System.out.println("-----------SHIFT---------------------------");
        System.out.println("string: "+string);
        for(int i=0; i<12; i++){
            string = UCripto.shiftString(string);
            System.out.println("\t"+string);
        }
    }
    
    @Test
    public void strongDESedeTest() {
        String key = "123456789012345678901234";
        System.out.println("-----------encryptStrongDESede---------------------------");
        String cript = UCripto.encryptStrongDESede(STRING_BASE, key);
        System.out.println(cript);
        String again = UCripto.decryptStrongDESede(cript, key);
        System.out.println(again);
        Assertions.assertEquals(STRING_BASE, again);
    }
    
    @Test
    public void mixItTest() {
        List<String> words = new ArrayList();
        words.add("alfa");
        words.add("beta");
        words.add("gama");
        words.add("teta");
        
        System.out.println("-----------mixItTest---------------------------");
        List<String> mixed = UCripto.mixIt(words);
        mixed.forEach(w->System.out.println("\t"+w));
    }

    @Test
    public void encryptDataAsPackageTest() {
        String plain;
        String password="HTdnei567!";
        
        List<String> words = new ArrayList<>();
        
        words.add("nicatara"); // 0
        words.add("robotera"); // 1
        words.add("toremina"); // 2
        words.add("peratico"); // 3
        words.add("tuberixa"); // 4
        
        System.out.println("-----------encryptDataAsPackageTest---------------------------");
        List<String> lines = UCripto.packData(HASH_BASE, password, words);
        lines.forEach(line->{
            System.out.println("\t"+line);
        });
        
        System.out.println("----------------- Data retrieved from ------------------------");
        plain = UCripto.unpackDataUsingPassword(lines.get(0), password);
        System.out.println("\t password  : "+plain);
        Assertions.assertEquals(HASH_BASE, plain);
        
        testSuccessFromLines(lines, 1, words, 0, 1);
        testSuccessFromLines(lines, 2, words, 0, 2);
        testSuccessFromLines(lines, 3, words, 0, 3);
        testSuccessFromLines(lines, 4, words, 0, 4);
        
        testSuccessFromLines(lines, 5, words, 1, 0);
        testSuccessFromLines(lines, 6, words, 1, 2);
        testSuccessFromLines(lines, 7, words, 1, 3);
        testSuccessFromLines(lines, 8, words, 1, 4);
        
        testSuccessFromLines(lines, 9, words, 2, 0);
        testSuccessFromLines(lines,10, words, 2, 1);
        testSuccessFromLines(lines,11, words, 2, 3);
        testSuccessFromLines(lines,12, words, 2, 4);
        
        testSuccessFromLines(lines,13, words, 3, 0);
        testSuccessFromLines(lines,14, words, 3, 1);
        testSuccessFromLines(lines,15, words, 3, 2);
        testSuccessFromLines(lines,16, words, 3, 4);
        
        testSuccessFromLines(lines,17, words, 4, 0);
        testSuccessFromLines(lines,18, words, 4, 1);
        testSuccessFromLines(lines,19, words, 4, 2);
        testSuccessFromLines(lines,20, words, 4, 3);
        
        boolean success = false;
        try{
            UCripto.unpackDataUsingPassword(lines.get(0), "otherpassword"); 
            success = true;
            throw new IllegalStateException("FAILED !!!");
        }catch(Exception e){}
        Assertions.assertFalse(success);

        testFailFromLines(lines,20, words, 0, 1);
        testFailFromLines(lines,19, words, 0, 2);
        testFailFromLines(lines,18, words, 0, 3);
        testFailFromLines(lines,17, words, 0, 4);
        
        testFailFromLines(lines,16, words, 1, 0);
        testFailFromLines(lines,15, words, 1, 2);
        testFailFromLines(lines,14, words, 1, 3);
        testFailFromLines(lines,13, words, 1, 4);
        
        testFailFromLines(lines,12, words, 2, 0);
        testFailFromLines(lines,11, words, 2, 1);
        testFailFromLines(lines,10, words, 2, 3);
        testFailFromLines(lines, 9, words, 2, 4);
        
        testFailFromLines(lines, 8, words, 3, 0);
        testFailFromLines(lines, 7, words, 3, 1);
        testFailFromLines(lines, 6, words, 3, 2);
        testFailFromLines(lines, 5, words, 3, 4);
        
        testFailFromLines(lines, 4, words, 4, 0);
        testFailFromLines(lines, 3, words, 4, 1);
        testFailFromLines(lines, 2, words, 4, 2);
        testFailFromLines(lines, 1, words, 4, 3);
    }
    
    private void testSuccessFromLines(List<String> lines, int indLine, List<String> words, int indWA, int indWB){
        String plain = UCripto.unpackDataUsingWords(lines.get(0), lines.get(indLine), words.get(indWA), words.get(indWB));
        System.out.println("\t words "+indWA+", "+indWB+": "+plain);
        Assertions.assertEquals(HASH_BASE, plain);
    }
    
    private void testFailFromLines(List<String> lines, int indLine, List<String> words, int indWA, int indWB){
        try{
            UCripto.unpackDataUsingWords(lines.get(0), lines.get(indLine), words.get(indWA), words.get(indWB));
        }catch(Exception e){
            return;
        }
        throw new IllegalStateException("FAILED !!!  "+indLine+" "+indWA+" "+indWB);
    }    
    
    public static void main(String[] arg)throws Exception{
        enrollTest();
    }
    
    public static void enrollTest() throws Exception{
        String password;
        String passConf;
        List<String> words;
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter   password: ");
        password = scanner.nextLine();
        System.out.print("Confirm password: ");
        passConf = scanner.nextLine();
        
        if(!password.equals(passConf)){
            throw new Exception("Password not match");
        }
        
        words = UCripto.getWords();
        
        System.out.println("Your words are:");
        words.forEach(w->System.out.print(w+" "));
        System.out.println();
        
        String content = "Safety box empty "+System.currentTimeMillis();
        List<String> lines = UCripto.packData(content, password, words);
        System.out.println("Your personal data pack is:");
        lines.forEach(line->{
            System.out.println("\t"+line);
        });
        
        words.clear();
        System.out.println("Enter your words again:");
        for(int i=0; i< UCripto.WORDS_AMOUNT; i++){
            System.out.print((i+1)+". ");
            words.add(scanner.nextLine());
        }
        UCripto.validateWords(lines, words);
    }
    
}
