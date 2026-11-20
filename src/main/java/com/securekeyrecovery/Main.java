
package com.securekeyrecovery;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        Scanner readthatInput = new Scanner(System.in);

        Path authFile = Path.of("holder.auth"); // stores five share holders salted password hashes.

        Path genThatGenFolder = Path.of("shares", "Generated Shares"); // where the freshly made shamir shares are created

        Path genThatSubFolder = Path.of("shares", "Submitted Shares"); // where holders submit shares upon recovery attempt

        try {

            if (!Files.exists(authFile)) { // configure the five fixed share holders on and only on the first run.

                System.out.println("Initial Share Holder Configuration");

                AuthenticateThatShareHolder.configShareHolders(authFile, readthatInput);

            }

        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {

            System.out.println("Account setup failed: " + e.getMessage());

            readthatInput.close();

            return;

        }

        boolean isRunning = true;

        while (isRunning) {

            System.out.println("\n#### Secure Key Recovery ####");

            System.out.println("1. Generate Keys, Encrypt File, and Create Shares");

            System.out.println("2. Recover Lost Key File");

            System.out.println("3. Decrypt File Using Key File");

            System.out.println("4. Exit");

            System.out.print("Select an option: ");

            String optionthisdudeChose = readthatInput.nextLine();

            switch (optionthisdudeChose) {

                case "1": {

                    try {

                        System.out.print("Enter file path to encrypt: "); // request the plaintext file to encrypt.

                        Path inputPath = Path.of(readthatInput.nextLine().trim());

                        if (!Files.isRegularFile(inputPath)) {throw new IOException("Input file does not exist.");

                        }

                        Path outputPath = Path.of(inputPath.toString() + ".skr");

                        Path keyPath = Path.of(inputPath.toString() + ".key"); // destination for the originally made keys

                        if (Files.exists(outputPath)) { // prevent accidental overwriting of encrypted data.

                            throw new IOException("Encrypted output file already exists.");

                        }

                        if (Files.exists(keyPath)) { throw new IOException("Original Key File Already Exists");

                        }

                        Files.createDirectories(genThatGenFolder); // make the folder for freshly made shares

                        Files.createDirectories(genThatSubFolder); // create the folder where holders will return their shares.

                        for (int id = 1; id <= 5; id++) { // ensure none of the intended share files exists.

                            Path sharePath = genThatGenFolder.resolve(outputPath.getFileName().toString() + ".holder" + id + ".skrs"

                            );

                            if (Files.exists(sharePath)) { throw new IOException("Share file already exists: " + sharePath);

                            }

                        }

                        SecretKey key = EncryptThatFile.genAESKey(); // generate independent encryption and authentication keys.

                        SecretKey hmacKey = AuthenticateThatFile.createthathmacKey();

                        byte[] iv = EncryptThatFile.generateInitializationVector();

                        byte[] pt = StoreThatFile.readthatFile(inputPath); // read the selected file before aes cbc encryption

                        byte[] ct = EncryptThatFile.encryptthemBytes(pt, key, iv); // encrypt using aes cbc

                        byte[] payload = StoreThatFile.saveprep4Encrypted(iv, ct); // prep file structure.

                        byte[] payloadTag = AuthenticateThatFile.authenticatedatPayload(payload, hmacKey); // authenticate our encrypted payload

                        StoreThatFile.writepreparedEncrypFile(outputPath, payload, payloadTag); // save encrypted file without storing hmac or aes key

                        StoreThatKey.saveThatKey(keyPath, key, hmacKey); // saves the original aes + hmac keys to a seperate key file.

                        System.out.println("Original key file: " + keyPath);

                        Map<Integer, byte[]> shares = RecoverThatKey.genShare(key, hmacKey); // split both keys into five Shamir recovery shares.

                        for (int id = 1; id <= 5; id++) { // save each share as its own file.

                            Path sharePath = genThatGenFolder.resolve(outputPath.getFileName().toString() + ".holder" + id + ".skrs"

                            );

                            StoreThatShare.saveSlice(sharePath, id, shares.get(id), outputPath);

                            System.out.println("Share Holder " + id + ": " + sharePath);

                        }

                        System.out.println("Encryption successful.");

                        System.out.println("Encrypted file: " + outputPath);

                        System.out.println("Recovery requires 3 distinct share holders.");

                    } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {

                        System.out.println("Encryption failed: " + e.getMessage());

                    }

                    break;

                }

                case "2": {

                    try {

                        System.out.print("Enter encrypted .skr file path: "); // choose the encrypted file associated with the lost key.

                        Path encryptedPath = Path.of(readthatInput.nextLine().trim());

                        if (!Files.isRegularFile(encryptedPath)) { throw new IOException("Encrypted file does not exist.");

                        }

                        if (!encryptedPath.toString().endsWith(".skr")) { throw new IOException("Expected a .skr encrypted file.");

                        }

                        Map<Integer, byte[]> collectedShares = new HashMap<>();

                        boolean cancelled = false;

                        while (collectedShares.size() < 3) { // require three authenticated Share Holders.

                            System.out.print("Share Holder ID (1-5, 0 to cancel): ");

                            String enteredId = readthatInput.nextLine().trim();

                            int id;

                            try {

                                id = Integer.parseInt(enteredId);

                            } catch (NumberFormatException e) {

                                System.out.println("Enter a valid numerical ID.");

                                continue;

                            }

                            if (id == 0) {

                                cancelled = true;

                                break;

                            }

                            if (id < 1 || id > 5) {

                                System.out.println("Invalid Share Holder ID.");

                                continue;

                            }

                            if (collectedShares.containsKey(id)) { // stops one holder from contributing their share twice.

                                System.out.println("This Share Holder already contributed.");

                                continue;

                            }

                            System.out.print("Password for Share Holder " + id + ": ");

                            char[] pass =
                                    readthatInput.nextLine().toCharArray();

                            boolean authenticated = AuthenticateThatShareHolder.verHold(authFile, id, pass); // verify PBKDF2 password hash before loading a share.

                            if (!authenticated) {

                                System.out.println("Authentication failed.");

                                continue;

                            }

                            Path sharePath = genThatSubFolder.resolve(
                                    encryptedPath.getFileName().toString() + ".holder" + id + ".skrs"
                            ); // load only this authenticated holder's submitted share.

                            StoreThatShare.shareSlice loaded =
                                    StoreThatShare.loadSlice(sharePath, encryptedPath);

                            if (loaded.id() != id) { // ensure the share number matches the account.

                                throw new IOException("Share Holder ID does not match share.");

                            }

                            collectedShares.put(id, loaded.data());

                            System.out.println("Share accepted. Total: " + collectedShares.size() + "/3");

                        }

                        if (cancelled) {

                            System.out.println("Recovery cancelled.");

                        } else {

                            RecoverThatKey.whatgotRecovered recovered = RecoverThatKey.reconKeys(collectedShares); // reconstruct AES and HMAC keys from three shares.

                            StoreThatFile.parseVF(encryptedPath, recovered.hmacKey()); // verify the reconstructed HMAC key against the encrypted file.

                            System.out.println("Cryptographic keys successfully reconstructed and verified.");

                            String encryptedName = encryptedPath.toString(); // identify the original file name by removing the .skr extension.

                            String originalName = encryptedName.substring(0, encryptedName.length() - 4);

                            Path recoveredKeyPath = Path.of(originalName + ".key.recovered"); // destination for replacement of lost key file.

                            StoreThatKey.saveThatKey(recoveredKeyPath, recovered.aesKey(), recovered.hmacKey()); // save reconstructed cryptographic keys.

                            System.out.println("Lost key file successfully recovered!");

                            System.out.println("Recovered key file: " + recoveredKeyPath);

                        }

                    } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {

                        System.out.println("Recovery failed: " + e.getMessage());

                    }

                    break;

                }

                case "3": {

                    try {

                        System.out.print("Enter encrypted .skr file path: "); // select the encrypted file to decrypt.

                        Path encryptedPath = Path.of(readthatInput.nextLine().trim());

                        if (!Files.isRegularFile(encryptedPath)) {

                            throw new IOException("Encrypted file does not exist.");

                        }

                        System.out.print("Enter original or recovered key file path: ");

                        Path keyPath = Path.of(readthatInput.nextLine().trim());

                        if (!Files.isRegularFile(keyPath)) {

                            throw new IOException("Key file does not exist.");

                        }

                        RecoverThatKey.whatgotRecovered keys = StoreThatKey.loadKey(keyPath); // load AES and HMAC keys from the selected key file.

                        StoreThatFile.encrypGrouping contents = StoreThatFile.parseVF(encryptedPath, keys.hmacKey()); // authenticate the encrypted file before decryption.

                        byte[] recoveredPlaintext = EncryptThatFile.decryptthemBytes(contents.ciphertext(), keys.aesKey(), contents.iv()); // decrypt ciphertext using the AES key.

                        Path recoveredPath = Path.of(encryptedPath.toString() + ".recovered");

                        Files.write(recoveredPath, recoveredPlaintext, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); // save decrypted file without overwriting an existing file.

                        System.out.println("Decryption successful.");

                        System.out.println("Decrypted file: " + recoveredPath);

                    } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {

                        System.out.println("Decryption failed: " + e.getMessage());

                    }

                    break;

                }

                case "4": {

                    isRunning = false;

                    break;

                }

                default: {

                    System.out.println("Invalid menu option.");

                    break;

                }

            }

        }

        readthatInput.close();

        System.out.println("Secure Key Recovery closed.");

    }

}
