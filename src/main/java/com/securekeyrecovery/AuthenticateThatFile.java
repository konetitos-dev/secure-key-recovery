package com.securekeyrecovery;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac; // import java class that computes mac
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.MessageDigest; // provides MessageDigest.isEqual() to allow us to compare auth tags securely.

public class AuthenticateThatFile {

    private static final SecureRandom rand = new SecureRandom(); // secure rand for generating the hmac keys.

    public static SecretKey createthathmacKey() throws GeneralSecurityException { // gens random 256 bit key for hmac-sha256 auth, throws security exception if fails

        KeyGenerator makedatKey = KeyGenerator.getInstance("HmacSHA256"); // configs key generator for hmac sha 256 alg

        makedatKey.init(256, rand); // makes the generator produce the 256 bit key leveraging secure randomness

        return makedatKey.generateKey(); // gens hmac key, returned to calling method.

    }

    public static byte[] assembledatHMAC(byte[] iv, byte[] ciphertext, SecretKey authkey) throws GeneralSecurityException { // computes hmac auth tag indepedently of the AES encrypt key.

        Mac macDaddy = Mac.getInstance("HmacSHA256"); // mac object configured to use hmac paired with sha 256

        macDaddy.init(authkey); // inits the mac with auth key

        macDaddy.update(iv); // includes the initialization vector calc to detect modification or integrity compromise.

        return macDaddy.doFinal(ciphertext); // integrates ct into mac calc and returns auth tag

    }

    public static boolean verifydatHMAC(byte[] iv, byte[] ciphertext, byte[] ogTag, SecretKey authkey) throws GeneralSecurityException { // recalculate hmac using provided iv ct and authkey

        byte[] calctheTag = assembledatHMAC(iv, ciphertext, authkey); // recalculation actually done here

        return MessageDigest.isEqual(calctheTag, ogTag); // compare them. on match return true for the boolean, if no match, returns false.

    }

    public static byte[] authenticatedatPayload(byte[] payload, SecretKey authkey) throws GeneralSecurityException { // gens a hmac tag for our payload.

        Mac macbigDaddy = Mac.getInstance("HmacSHA256"); // mac object configed for hmac sha 256

        macbigDaddy.init(authkey); // init mac utilizing auth key

        return macbigDaddy.doFinal(payload); // computes, returns 32 byte auth tag

    }

    public static boolean verifydatPayload(byte[] payload, byte[] ogTag, SecretKey authkey) throws GeneralSecurityException { // verification, compares tags

        byte[] calcTag = authenticatedatPayload(payload, authkey); // recalculates

        return MessageDigest.isEqual(calcTag, ogTag); // compares original to new, false if no match true if yes match.

    }

}