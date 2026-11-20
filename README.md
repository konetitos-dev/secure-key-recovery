Secure Key Recovery v1

A Java command-line application utilizing secure file encryption and distributed cryptographic key recovery using Shamir's Secret Sharing.

##Features##

-AES-256-CBC file encryption.
-HMAC-SHA256 based integrity and authenticity verification.
-3-of-5 Shamirs Secret Sharing to reconstruct lost keys.
-Five password-authenticated shareholders using salted password hashing, configured at first run.
-Integrity checks against submitted shares.
-File Decryption using original key or reconstructed key file

--Requires Java 25, or newer.

## Technologies ##

- Java
- Apache Maven
- JCA
- Shamir's Secret Sharing library (com.codahale:shamir)

  ## Considerations ##

  Initially developed as a final project for a course to demonstrate threshold based key recovery and cryptographic file protection. Not inherently very secure, but fun to play around with and examine for educational purposes. Might be expanded upon functionally in the future with a dedicated GUI, tamper evident audit logging, and centralized identity management systems.
