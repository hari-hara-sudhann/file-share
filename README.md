# File Sharer

`file-sharer` is a small Java command-line application for encrypted peer-to-peer file transfers over a local network.
It uses RSA for public-key exchange and AES for the actual file payload encryption.

## Project Layout

```text
file-sharer/
├── pom.xml
├── README.md
├── docs/
│   └── overview.md
└── src/
    └── main/
        └── java/
            ├── EncryptedData.java
            ├── FileReceive.java
            ├── FileSend.java
            └── FileShare.java
```

## What Each Area Does

- `src/main/java/`: application source code.
- `docs/`: extra project notes and overview material.
- `pom.xml`: Maven build definition.

## Build

Compile and package the project with Maven:

```bash
mvn package
```

That creates an executable jar at:

```text
target/fileshare.jar
```

## Run

Show CLI help:

```bash
java -jar target/fileshare.jar --help
```

Show version:

```bash
java -jar target/fileshare.jar --version
```

Show author:

```bash
java -jar target/fileshare.jar --who-did-this
```

Start the sender:

```bash
java -jar target/fileshare.jar send /absolute/path/to/file.ext
```

Start the receiver:

```bash
java -jar target/fileshare.jar receive 192.168.1.20 2006
```

Or write to a specific output path:

```bash
java -jar target/fileshare.jar receive 192.168.1.20 2006 /absolute/path/to/output.ext
```

## Key Storage

The app no longer stores runtime key files in the project root.

- Sender keys: `~/.fileshare/send/public.key` and `~/.fileshare/send/private.key`
- Receiver keys: `~/.fileshare/receive/public.key` and `~/.fileshare/receive/private.key`

If those files do not exist, the application generates them automatically.

## Notes

- The sender listens on TCP port `2006`.
- The receiver must connect using the sender IP and printed port.
- Runtime logging is intentionally very verbose for troubleshooting and protocol visibility.
