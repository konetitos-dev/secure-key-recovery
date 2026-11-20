package com.securekeyrecovery;

import javax.crypto.KeyGenerator; // imports javas util for generating crypto keys
import javax.crypto.SecretKey; // imports the interface necessary to represent a symmetric key
import java.security.GeneralSecurityException;  // gives us the necessary exception type for cryptography failures.
import java.security.SecureRandom; // import javas secure random number gen
import javax.crypto.Cipher; // gives us crypto encryption and decryption ops
import javax.crypto.spec.IvParameterSpec; // represents the initialization vector that we end up passing to the cipher


public class EncryptThatFile { // class declaration for file encryption ops

    private static final SecureRandom rand = new SecureRandom(); // creates secure random object rand, only can be used in this class. static and final so the whole class can use it and cannot be assigned to a different generator

    public static SecretKey genAESKey() throws GeneralSecurityException { // method for generating and returning a random AES key. public so main can grab it. throws allows for error handling.

        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // creates key generator, for making AES keys.

        keyGen.init(256, rand); // initializes with keysize 256 bits

        return keyGen.generateKey(); // gens the key, returns to its calling method.

    }

    public static byte[] generateInitializationVector() { // method for making and returning our iv

        byte[] loadbearingIv = new byte [16]; // gives us a 16 byte array to work with, needed since AES uses a 128 bit block size

        rand.nextBytes(loadbearingIv); // fills up our array with secure random bytes

        return loadbearingIv; // returns

    }

    public static byte[] encryptthemBytes(byte[] plaintext, SecretKey key, byte[] iv) throws GeneralSecurityException { // encrypts pt using our AES key and IV

        Cipher superimportantCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Creates said cypher, primed for AES CBC utilizing PKCS5 for padding

        superimportantCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)); // initializes our cipher for encryp. with the key and IV.

        return superimportantCipher.doFinal(plaintext); // encrypts the pt, returns ct.

    }

    public static byte[] decryptthemBytes(byte[] ciphertext, SecretKey key, byte[] iv) throws GeneralSecurityException {

        Cipher supermegaimportantCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        supermegaimportantCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv)); // essentially the same as encrypt them bytes, but this line here is the takeaway, primes for decrypt mode

        return supermegaimportantCipher.doFinal(ciphertext); // decrypts ct, returns pt

    }

}
