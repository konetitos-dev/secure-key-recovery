package com.securekeyrecovery;

import java.io.IOException; // allows i/o operations
import java.nio.file.Files; // methods for interacting with said files
import java.nio.file.Path; // represents locations in the file system
import java.io.ByteArrayOutputStream; // gives us a dynamic buffer for bytes
import java.io.DataOutputStream; // allows writing of binary data
import java.nio.file.StandardOpenOption; // gives us control on how java creates output files
import java.security.GeneralSecurityException;
import java.util.Arrays; // lets us use array operations
import javax.crypto.SecretKey; // represents the HMAC auth key
import java.io.ByteArrayInputStream; // lets binary data stored in memory be read as an input stream
import java.io.DataInputStream; // enables reading of structured binary values


public class StoreThatFile { // used for file reading and encryption data storage

    public static byte[] readthatFile(Path wherefileLives) throws IOException { // reads file path "where it lives", read can fail, so include IO exception.

        return Files.readAllBytes(wherefileLives); // reads entire file into a byte

    }

    public static byte[] saveprep4Encrypted(byte[] iv, byte[] ciphertext) throws IOException { // makes our binary payload, has metadata, an IV, and ct, throws io exception if write error occurs

        if (iv.length != 16 || ciphertext.length == 0 || ciphertext.length % 16 != 0) { // validation. checks that the iv is 16 bytes and the ct has a complete AES block.

            throw new IllegalArgumentException("Invalid IV or ciphertext length."); // rejects if invalid

        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(); // creates our dynamic buffer

        try (DataOutputStream output = new DataOutputStream(buffer)) { // wraps the buffer in an output stream for writing binary

            output.write(new byte[]{'S', 'K', 'R', 'F'}); // writes our identifier for recognizing encrypted files in our program.

            output.writeByte(1); // file format as one byte v1

            output.write(iv); // writes the iv to our buffer

            output.writeInt(ciphertext.length); // writes the ct length as an int for parsing later on

            output.write(ciphertext); // appends file contents after metadata is written.

        }

        return buffer.toByteArray(); // converts information in memory into byte[]. returns.

    }

    public static void writepreparedEncrypFile(Path dest, byte[] payload, byte[] hmacTag) throws IOException { // writes payload to dest file

        if (hmacTag.length != 32) {
            throw new IllegalArgumentException("HMAC tag length is invalid..."); // verfies tag is proper size, rejects if not

        }

        ByteArrayOutputStream buff = new ByteArrayOutputStream(); // buffer for creating complete file

        buff.writeBytes(payload); // appends the payload, header, iv, and ct.

        buff.writeBytes(hmacTag); // slaps our 32-byte hmac tag in there after inital payload.

        Files.write(dest, buff.toByteArray(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); // writes file to disk, avoids overwritting existing files.

    }

    public static byte[] readthethingwejustEncrypted(Path src, SecretKey authkey) throws IOException, GeneralSecurityException { // reads encrypt file and checks its hmac before returning its payload

        byte[] fd = Files.readAllBytes(src); // reads the source file into working memory

        if (fd.length < 73) {
            throw new IOException("File malformed and or incomplete"); // checks to ensure min valid file size, rejects malformed or incomplete encryptions.


        }

        int loP = fd.length - 32; // exclude auth tag in payload length calculations

        byte[] payload = Arrays.copyOfRange(fd, 0, loP); // extracts encrypted file header, excluding hmac tag.

        byte[] storethatTagIG = Arrays.copyOfRange(fd, loP, fd.length); // extracts hmac tag

        if (!AuthenticateThatFile.verifydatPayload(payload, storethatTagIG, authkey)) { // recompute and verify

            throw new GeneralSecurityException("File Authentication Failed"); // rejects if no hmac match

        }

        return payload; // returns if payload auths for decryption

    }

    public record encrypGrouping(byte[] iv, byte[] ciphertext) { // groups extracted iv and ct together for return

    }

    public static encrypGrouping parseVF(Path src, SecretKey authkey) throws IOException, GeneralSecurityException { // reads, authenticates, and parses the file

        byte[] payload = readthethingwejustEncrypted(src, authkey); // authenticates before parsing

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) { // reads payload as bin data

            byte[] id = new byte[4]; // allocs space four the 4-byte skrf file identifier.

            in.readFully(id); // reads identifier from begginig

            if (!Arrays.equals(id, new byte[]{'S', 'K', 'R', 'F'})) { // is this our recognized file format?

                throw new IOException("Wrong file format"); // rejects improper format

            }

            int ver = in.readUnsignedByte(); // read format as unsigned byte

            if (ver != 1) { // do we support

                throw new IOException("Unsupported version.");

            }

            byte[] iv = new byte[16]; // Allocate space for our AES IV

            in.readFully(iv); // grabs og 16 bytes iv needed to decrypt.

            int ctLen = in.readInt(); //reads ct lengt from file head

            if (ctLen < 16 || ctLen % 16 != 0 || ctLen != payload.length - 25) { // validation for ct size when held against AES size requirements and payload length

                throw new IOException("Invalid CT length.");

            }

            byte[] ct = new byte[ctLen]; // alloc needed space for the document

            in.readFully(ct); // take ct from auth payload.

            return new encrypGrouping(iv, ct); // returns both values for decryption

        }
    }
}