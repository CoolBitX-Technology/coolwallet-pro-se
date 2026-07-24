# CoolWallet Pro Firmware

![CoolWallet Pro Firmware Logo](coolwallet-pro-firmware-logo.png)

[Official Website](https://www.coolwallet.io/)｜[Discord](https://discordapp.com/channels/640544929680064512/660894930604130304/) | [Twitter Follow](https://twitter.com/coolwallet)

## Introduction
CoolWallet Pro Firmware is a Javacard firmware designed specifically for the [CoolWallet Pro](https://www.coolwallet.io/coolwallet_pro/). It offers advanced features for private key management, signing, and transaction data composition. The firmware focuses on developing a secure element solution using Java Card technology to ensure a high level of security for cryptographic operations and the protection of sensitive data.

### Key Features

- **Private key management**: Safely store and manage private keys within the secure element of the CoolWallet Pro.
- **Signing**: Perform secure and verifiable digital signatures for transactions and authentication purposes.
- **Transaction data composition**: Generate and compose transaction data in a secure manner, ensuring data integrity and confidentiality.

### Security and Privacy

The CoolWallet Pro Firmware prioritizes security and privacy to protect users' digital assets. It leverages the advanced security features of Java Card technology, providing a robust and tamper-resistant environment for cryptographic operations. With the CoolWallet Pro Firmware, users can have confidence in the confidentiality, integrity, and authenticity of their transactions and sensitive data.

### Supported Algorithms
#### Hash:
- Blake2b
- HmacSha
- Sha2
- Sha3
- Ripemd

#### Signature:
- Ed25519
- Secp256k1
- Curve25519
- Bip32-Ed25519 (Cardano Signature)

## Project Installation (Common)

To install the project, please follow the steps below:
### Step 1: Cloning the Repository
Clone the repository by running the following command in your terminal or command prompt:

```bash
git clone git@github.com:CoolBitX-Technology/coolwallet-pro-se.git
```

### Step 2: Initialize and Update Submodule
Initialize and update the submodule by running the following commands:
```shell
$ git submodule init
$ git submodule update
```

### Step 3: Run the Installation Script
Run the installation script by executing the following command:
```shell
$ cd coolwallet-pro-se-crypto
$ javac Installation.java
$ java Installation
```

>**Note:** The Crypto Library is an internal library provided by CoolBitX, offering a range of encoding and digital signature algorithms.

>**Windows Note:** This script creates **symbolic links** from `src/coolbitx/` to the files in `coolwallet-pro-se-crypto/src/`. Creating a symbolic link on Windows requires the `SeCreateSymbolicLinkPrivilege`, which a standard user account does not have by default. If you run the commands above from a normal (non-elevated) terminal, symlink creation will fail with an `AccessDeniedException` and Eclipse will show the crypto classes (`Sha2`, `Ed25519`, etc.) as missing/unresolved. To fix this, do **one** of the following before running `java Installation`:
>- Enable **Developer Mode** (Settings → Update & Security → For developers → Developer Mode), or
>- Run your terminal/command prompt **as Administrator**.
>
>You only need elevated privileges at the moment the links are *created* — once the symlinks exist, opening and building the project in Eclipse afterwards works normally with a regular user account. If you ever re-run `java Installation` (e.g. after new files are added to the crypto library), repeat this with an elevated/Developer Mode session.

## Environment Setup

This project supports two development workflows:
1.  **Windows (Eclipse)**: Official NXP JCOP Tools workflow for CAP file generation.
2.  **Cross-Platform (CLI / VS Code)**: Script-based workflow for macOS, Linux, and Windows (WSL), supporting local simulation.

---

## 1. Windows Environment Setup (Eclipse)

To successfully build and set up the development environment for this project on **Windows** using Eclipse, please follow the instructions below:

### Prerequisites
- [JDK 8](https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html) (64-bit)

### Setting Up Environment Variables

After installing Java, it is essential to set up environment variables on your **Windows** computer.

##### System Variables
- `JAVA_HOME`: Set the path to the JDK installation directory.
- `PATH`: Add the following paths to the system's `PATH` variable:
  - `%JAVA_HOME%\bin`
  
### Required Tools Installation
To ensure a smooth compilation process, it is recommended to have the following programs and versions installed:

- [Eclipse Luna](https://www.eclipse.org/downloads/packages/release/luna/sr2/eclipse-ide-java-developers)
- JCOP_Tools_5.32.0.4



### JCOP Tools Installation

1. Download the JCOP Tools installation package and save it to a directory of your choice.
2. Launch Eclipse IDE.
3. From the menu bar, go to  **Help > Install New Software**.
4. In the Install dialog, click on **Add** to add new features.
5. In the Add Site dialog:
   - Provide a descriptive name, such as 'NXP JCOP Tools'.
   - If you have unpacked the JCOP Tools package, select **Local...** and navigate to the root folder of JCOP Tools.
   - If JCOP Tools is a ZIP file, select **Archive...** and navigate to the ZIP file.
6. Restart Eclipse to complete the installation.

### Activating JCOP Tools

1. Open Eclipse and navigate to **File > New > Java Card Project**.
2. Choose the appropriate wizard:
   - Create a Java Card project.
   - Select the licensed JCOP: JCOP_Tools_activation_workspace.

### Library Setup (Required)

Before opening the project in Eclipse, you must place the following library files into `local_lib/javacard-libs/`:

| File | Source |
|------|--------|
| `api_classic.jar` | Extracted from `NXP_JCOP_Plugin_5.32.0.4.zip` |
| `JCOPx_API-R1.1.4.jar` | Extracted from `NXP_JCOP_Plugin_5.32.0.4.zip` |
| `bcprov-jdk15on-1.70.jar` | [Maven Central](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/bcprov-jdk15on-1.70.jar) |

These files are referenced by the project's `.classpath` and are required for Eclipse to compile the source successfully.

If you are on macOS/Linux, you can run `scripts/setup-libs.sh` to extract these automatically. On Windows, you can obtain the first two jars by extracting `NXP_JCOP_Plugin_5.32.0.4.zip` and locating them inside the plugin bundle, or request a pre-packaged zip from a teammate who has already run the setup script.

---

## 2. Cross-Platform Environment Setup (CLI / VS Code)

This workflow is recommended for users on **macOS**, **Linux**, or **Windows (WSL)** who prefer using command-line tools or VS Code/Cursor. It supports compiling, simulating (without a physical card), and generating CAP files.

### Prerequisites
- A JDK on `JAVA_HOME` (or just on `PATH`) — the build scripts compile via the bundled ECJ compiler (`lib/ecj-*.jar`), which always targets JavaCard-compatible bytecode (`-source/-target 1.5`) regardless of which JDK runs it, so any JDK works (verified against 8, 11, and 17). If `lib/ecj-*.jar` is ever missing, the scripts fall back to your JDK's own `javac`, which *does* need to be JDK 8 — `-source/-target 1.5` was dropped in later `javac` versions.
- Gradle (for downloading simulator dependencies)

### Configuration

#### 1. VS Code Configuration (Optional)

This tells the **VS Code Java extension** where a JDK 8 is so that IDE features (code completion, error highlighting, etc.) work correctly — the project's `.classpath` declares its execution environment as `JavaSE-1.8` (matching the JavaCard-compatible bytecode target above), independently of whichever JDK the build scripts use. It has no effect on the build scripts themselves.

The project's `.vscode/settings.json` already configures VS Code to auto-detect Java 8, so no manual changes are needed in most cases.

If auto-detection fails (e.g., multiple JDKs installed and the wrong one is picked), you can pin the path explicitly in `.vscode/settings.json`:

```json
{
    "java.configuration.runtimes": [
        {
            "name": "JavaSE-1.8",
            "path": "/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home", // Set your Java 8 path here
            "default": true
        }
    ]
}
```

### Workflow

#### Step 1: Initial Setup (One-time)

Before running the setup script, you must obtain the **NXP JCOP Plugin** (version 5.32.0.4) and place it in the `local_lib` directory.

1.  Obtain `NXP_JCOP_Plugin_5.32.0.4.zip`.
2.  Ensure the `local_lib` directory exists (create it if needed):
    ```bash
    mkdir -p local_lib
    ```
3.  Place the file at: `local_lib/NXP_JCOP_Plugin_5.32.0.4.zip`.

Run the setup script to extract dependencies:

```bash
chmod +x scripts/setup-libs.sh
scripts/setup-libs.sh
```

#### Step 2: Build the Project

To compile the JavaCard applet:

```bash
chmod +x scripts/build.sh
scripts/build.sh
```

`scripts/build.sh` will:
- Compile all `.java` files under `src/` to JavaCard-compatible bytecode
- Use the JavaCard / JCOP jars in `local_lib/javacard-libs` as the classpath
- Output `.class` files into the `bin/` directory

#### Step 3: Run the Simulator (Web Service)

To start the APDU simulation web service on port 9527:

```bash
chmod +x scripts/run-web-server.sh
scripts/run-web-server.sh
```

This service allows you to send APDUs via HTTP POST to `http://localhost:9527/apdu`.
Example:
```bash
curl -X POST http://localhost:9527/apdu -d '00A404000D436F6F6C57616C6C657450524F'
```

#### Step 4: Generate CAP files

After compilation, you can generate CAP files with the following commands:

```bash
chmod +x scripts/build-cap.sh
scripts/build-cap.sh
```

This script will:
- Read `.class` files from the `bin/` directory
- Use the JavaCard converter in `local_lib/javacard-libs/tools.jar`
- Use export files in `local_lib/javacard-libs/api_export_files`
- Produce two CAP packages:
  - Main applet: `coolbitx` (main applet, AID `CoolWalletPRO`)
  - SIO applet: `coolbitx.sio` (StoreApplet, AID `BackupApplet`)

CAP output locations:
- Main package: `bin/coolbitx/javacard/`
- SIO package: `bin/coolbitx/sio/javacard/`

---


## License
This project is licensed under the [CoolBitX Limited Use License](LICENSE).

## Security Vulnerability Disclosure

If you discover any security vulnerabilities, please contact bounty@cbx.io For more details, refer to the [Bounty Project](https://bugrap.io/bounties/CoolWallet). Do not disclose the content directly on public forums.

Feel free to contact us for any inquiries or support.
