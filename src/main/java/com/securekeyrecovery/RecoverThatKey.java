package com.securekeyrecovery;

import com.codahale.shamir.Scheme; // imports shamir library by codahale.
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;


public class RecoverThatKey {

    private static final Scheme skeem = new Scheme(new SecureRandom(), 5, 3); // configure shamirs for 5 total shares, requires 3 to reconstruct.

    public record whatgotRecovered(SecretKey aesKey,
                                   SecretKey hmacKey) { // makes a record to hold both keys post reconstruction

    }

    public static Map<Integer, byte[]> genShare(SecretKey aesKey, SecretKey hmacKey) {

        byte[] aesChomps = aesKey.getEncoded();
        // grab raw bytes of the aes hmac keys
        byte[] hmacChomps = hmacKey.getEncoded();

        if (aesChomps == null || hmacChomps == null || aesChomps.length != 32 || hmacChomps.length != 32) { // validation block

            throw new IllegalArgumentException("Invalid key length dude."); // handle invalid length

        }

        byte[] tbs = new byte[64]; // creates a 64 byte array to hold the 256 bit keys.

        System.arraycopy(aesChomps, 0, tbs, 0, 32); // copies 32 byte aes key into first half

        System.arraycopy(hmacChomps, 0, tbs, 32, 32); // copies hmac key to second half

        try {

            return skeem.split(tbs); // gen the five shares

        } finally {

            Arrays.fill(tbs, (byte) 0); // clear temp secret from mem

            Arrays.fill(aesChomps, (byte) 0); // clear temp aes key from array

            Arrays.fill(hmacChomps, (byte) 0); // clear temp hmac key from array

        }

    }

    public static whatgotRecovered reconKeys(Map<Integer, byte[]> potp) { // potp represents shares... stands for pieces  of the pie

        if (potp == null || potp.size() < 3 || potp.size() > 5) {

            throw new IllegalArgumentException("Requires 3 of 5 shares..."); // requires 3 distinct shares, no more than the whole.

        }

        for (Map.Entry<Integer, byte[]> entry : potp.entrySet()) { // check share ids and their size.

            Integer id = entry.getKey();

            byte[] pop = entry.getValue();

            if (id == null || id < 1 || id > 5 || pop == null || pop.length != 64) {
                throw new IllegalArgumentException("Invalid Share.");

            }

        }

        byte[] tbs = skeem.join(potp); // reconstruct original secret using shamirs.

        try {

            SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(tbs, 0, 32), "AES"); // restores aes key from the first 32 bytes

            SecretKey hmacKey = new SecretKeySpec(Arrays.copyOfRange(tbs, 32, 64), "HmacSHA256"); // restores hmac from remaining bytes

            return new whatgotRecovered(aesKey, hmacKey); // returns recovered key

        } finally {

            Arrays.fill(tbs, (byte) 0); // clears the temp reconstruction from working memory.

        }

    }

}