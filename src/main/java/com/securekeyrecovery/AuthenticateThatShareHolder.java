package com.securekeyrecovery;

import javax.crypto.SecretKeyFactory; // import, lets us perform computation
import javax.crypto.spec.PBEKeySpec; // allows us to detail how we want our hash derived.
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Scanner;


public class AuthenticateThatShareHolder {

    private static final SecureRandom rand = new SecureRandom(); // each participant needs a 16 byte salt

    private static final int ITERATIONS = 210000; // PBKDF2 intentially makes bruteforce computationally expensive.

    private static byte[] hashPass(char[] pass, byte[] salt) throws GeneralSecurityException { // derives 256 bit hash utilizing pbkdf2 hmac sha 256

        PBEKeySpec thing = new PBEKeySpec(pass, salt, ITERATIONS, 256);

        try {

            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(thing).getEncoded();

        } finally {

            thing.clearPassword();

        }

    }

    public static void configShareHolders(Path authFile, Scanner readthatInput) throws IOException, GeneralSecurityException {

        if (Files.exists(authFile)) {
            throw new IOException("Holder Account Exists"); // does not overwrite an existing participant credential file.

        }

        ByteArrayOutputStream buff = new ByteArrayOutputStream(); // prepare cred data in working memory before we write it.

        try (DataOutputStream out = new DataOutputStream(buff)) {

            out.write(new byte[]{'S', 'K', 'R', 'A'}); // cred file identifier.

            out.writeByte(1); // version

            for (int id = 1; id <= 5; id++) { // for loop, allows us to configure all accounts on initial setup.

                boolean valPass = false;

                while (!valPass) { // keep asking holder untill pass is valid.

                    System.out.print("Set password for Share Holder" + id + ": ");

                    char[] pass = readthatInput.nextLine().toCharArray();

                    try {

                        if (pass.length < 8) { // password length requirement to increase security, this is a demo though so we wont get too crazy like special characters and stuff.

                            System.out.println("Password must be 8 characters or more!");

                            continue;

                        }

                        byte[] salt = new byte[16]; // allocates salt that bad boy

                        rand.nextBytes(salt); // generate the salt

                        byte[] hash = hashPass(pass, salt); // derive our salted hash.

                        try {

                            out.write(salt); // store the salt

                            out.write(hash); // store the hash

                            valPass = true; // sucessfull configuration, move to next holder

                        } finally {

                            Arrays.fill(hash, (byte) 0); // clear the temp hash bytes in mem.

                        }

                    } finally {

                        Arrays.fill(pass, '\0'); // clear temp pass char array in mem

                    }

                }

            }

        }

        if (Files.getFileStore(authFile.toAbsolutePath().getParent()).supportsFileAttributeView("posix")) { // check if filesystem supports posix permissions

            Files.createFile(authFile, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); // create auth file with owner only permissions

            Files.write(authFile, buff.toByteArray(), StandardOpenOption.WRITE); // write password salts and hashes to protected file

        } else {

            Files.write(authFile, buff.toByteArray(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); // windows fallback using filesystem inherited permissions ps, get linux please. if you're reading this on mac, god bless your soul.

        }

        System.out.println("Share Holder Accounts Configured!"); // confirmation output

    }

    public static boolean verHold(Path authFile, int id, char[] pass) throws IOException, GeneralSecurityException {

        try {

            if (id < 1 || id > 5) {
                throw new IllegalArgumentException("Invalid Share Holder ID"); // only original 5 may have an account.

            }

            byte[] fd = Files.readAllBytes(authFile); // load saved creds

            if (fd.length != 245) {
                throw new IOException("Invalid credential file length"); // verifies cred file length. Header's 5 bytes. We have five accounts, at 48 bytes each.

            }

            if (!Arrays.equals(Arrays.copyOfRange(fd, 0, 4), new byte[]{'S', 'K', 'R', 'A'}) || fd[4] != 1) {
                throw new IOException("Invalid cred file formate.");

            }

            int offset = 5 + (id - 1) * 48; // logic for finding the account record

            byte[] salt = Arrays.copyOfRange(fd, offset, offset + 16);

            byte[] storedHash = Arrays.copyOfRange(fd, offset + 16, offset + 48);

            byte[] enteredHash = null; //

            try {

                enteredHash = hashPass(pass, salt); // derive the new hash utilizing provided password and salt

                return MessageDigest.isEqual(storedHash, enteredHash); // authentication succeeds if both hashes match.

            } finally {

                if (enteredHash != null) {

                    Arrays.fill(enteredHash, (byte) 0); // clear hash

                }

                Arrays.fill(storedHash, (byte) 0); // clear stored hash copy even if pbkdf2 throws exception

            }

        } finally {

            if (pass != null) {

                Arrays.fill(pass, '\0');

            }

        }

    }

}