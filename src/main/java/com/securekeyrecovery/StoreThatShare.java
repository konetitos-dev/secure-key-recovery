package com.securekeyrecovery;

import java.io.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.nio.file.attribute.PosixFilePermissions;


public class StoreThatShare {

    public record shareSlice(int id, byte[] data) { // holds share id and info

    }

    private static byte [] fp(Path encryptedFile) throws IOException, GeneralSecurityException { // calc fingerprint for id'ing associated encryp file.

        return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(encryptedFile));

    }

    public static void saveSlice(Path destination, int id, byte[] slice, Path encryptedFile) throws IOException, GeneralSecurityException { // saves a share without overwriting

        if (id < 1 || id > 5 || slice == null || slice.length != 64) {
            throw new IllegalArgumentException("Invalid Recovery Share...");

        }

        byte[] docFP = fp(encryptedFile); // calculate fingerprint

        if (Files.getFileStore(destination.toAbsolutePath().getParent()).supportsFileAttributeView("posix")) { // check if filesystem supports posix perms

            Files.createFile(destination, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))); // create share file with owner only permissions

        } else {

            Files.createFile(destination); // fallback for windows or other non-posix systems once again, get linux plz

        }

        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(destination, StandardOpenOption.WRITE))) {

            out.write(new byte[] {'S','K','R','S'}); // share file id.

            out.writeByte(1); // version

            out.writeByte(id); // share num

            out.write(docFP); // write fp calced earlier

            out.write(slice); // shamir share or "Slice" data.

        }

    }

    public static shareSlice loadSlice(Path source, Path encryptedFile) throws IOException, GeneralSecurityException { // loads share and checks associated file.

        byte[] fd = Files.readAllBytes(source); // reads file to mem.

        if (fd.length != 102) {
            throw new IOException("Invalid share file length..."); // validate share file size

        }

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(fd))) { // structured binary field reading

            byte[] warlock = new byte[4]; // allocs space of share file id

            in.readFully(warlock); // extract id

            if (!Arrays.equals(warlock, new byte[]{'S', 'K', 'R', 'S'})) {
                throw new IOException("Invalid share file identifier...");

            }

            int version = in.readUnsignedByte(); // read format version

            int id = in.readUnsignedByte(); // read numeric id.

            if (version != 1 || id < 1 || id > 5) {
                throw new IOException("Unsupported Version / Share ID Error");

            }

            byte[] storedFP = new byte[32]; // alloc for stored fp

            in.readFully(storedFP); // read the fp on share creation

            if (!MessageDigest.isEqual(storedFP, fp(encryptedFile))) {
                throw new IOException("Share does not belong to this file!");

            }

            byte[] slice = new byte[64];  // alloc for the shamir share

            in.readFully(slice); // extract said share data

            return new shareSlice(id, slice); // returns id and slice info together

        }

    }

}