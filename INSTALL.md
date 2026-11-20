# Installation

Secure Key Recovery requires **Java 25 or newer**.

Download and extract `SecureKeyRecovery-v1.0.0.zip`, then open a terminal inside the extracted `SecureKeyRecovery` directory.

### Linux / macOS

```bash
java -cp "SecureKeyRecovery-1.0-SNAPSHOT.jar:lib/*" com.securekeyrecovery.Main
```

### Windows (PowerShell / Command Prompt)

```powershell
java -cp "SecureKeyRecovery-1.0-SNAPSHOT.jar;lib/*" com.securekeyrecovery.Main
```

**Note:** Run the command from the extracted directory, keeping the JAR and `lib` folder together. The application creates its working files and share directories as needed. Generated keys can then be distributed as seen fit. To Reconstruct, move keys to Submitted Shares folder and select reconstruction option in CLI.
