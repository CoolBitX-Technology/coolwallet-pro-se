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

## Environment Setup

To successfully build and set up the development environment for this project on **Windows**, please follow the instructions below:

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

## Installation
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

## Building the Project
After executing the `Installation` script, proceed with the following steps in Eclipse:
1. Click on **Project > Clean**.
2. Check the box for **Clean projects selected below**.
3. Select **CoolWalletS_3rd** project.
4. Check the box for **Start a build immediately**.
5. Check the box for **Build only the selected projects**.

Upon successful build completion, the `coolbitx.cap` file will be generated in the following location: `\coolwallet-pro-se\bin\coolbitx\javacard`.

## License
This project is licensed under the [CoolBitX Limited Use License](LICENSE).

## Security Vulnerability Disclosure

If you discover any security vulnerabilities, please contact bounty@cbx.io For more details, refer to the [Bounty Project](https://bugrap.io/bounties/CoolWallet). Do not disclose the content directly on public forums.

Feel free to contact us for any inquiries or support.
