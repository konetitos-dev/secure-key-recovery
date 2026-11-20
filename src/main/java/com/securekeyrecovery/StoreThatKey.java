package com.securekeyrecovery;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.nio.file.attribute.PosixFilePermissions; // allows us to restrict read permissions to only be readable and writeable by the specific user.

public class StoreThatKey {

    public static void saveThatKey(Path dest, SecretKey aesKey, SecretKey hmacKey) throws IOException { // saves aes and hmac keys together, as one 64-byte key file.

        byte[] aesChomps = aesKey.getEncoded();

        byte[] hmacChomps = hmacKey.getEncoded();

        if (aesChomps == null || hmacChomps == null || aesChomps.length != 32 || hmacChomps.length != 32) {
            throw new IllegalArgumentException("Invalid Key Length"); // both keys must be exactly 32 bytes.

        }

        byte[] combo = new byte[64];

        try {

            System.arraycopy(aesChomps, 0, combo, 0, 32); // store the aes key in bytes 0-31

            System.arraycopy(hmacChomps, 0, combo, 32, 32); // store hmac in 32-63

            if (Files.getFileStore(dest.toAbsolutePath().getParent()).supportsFileAttributeView("posix")) { // check if filesystem supports posix permissions

                Files.createFile(dest, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); // create key file with owner only perms

                Files.write(dest, combo, StandardOpenOption.WRITE); // write combined keys to protected file

            } else {

                Files.write(dest, combo, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); // for windows or other non-posix systems ps. please just use linux man.

            }

        } finally {

            Arrays.fill(combo, (byte) 0); // clear temp copies of key material

            Arrays.fill(aesChomps, (byte) 0);

            Arrays.fill(hmacChomps, (byte) 0);

        }

    }

    public static RecoverThatKey.whatgotRecovered loadKey(Path src) throws IOException { // load original, or reconstructed key file.

        byte[] combo = Files.readAllBytes(src);

        try {

            if (combo.length != 64) {
                throw new IOException("Invalid Key File Length."); // key file MUST be 64 bites.


            }

            SecretKey aesKey = new SecretKeySpec(combo, 0, 32, "AES"); // recreate aes key from first 32 bytes

            SecretKey hmacKey = new SecretKeySpec(combo, 32, 32, "HmacSHA256"); // recreates hmac from remaining bytes

            return new RecoverThatKey.whatgotRecovered(aesKey, hmacKey); // returns the thing

        } finally {

            Arrays.fill(combo, (byte) 0); // clear temp combo key array

        }
    }
}