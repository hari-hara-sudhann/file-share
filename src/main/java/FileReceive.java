import java.io.*;
import java.net.*;
import java.nio.file.FileAlreadyExistsException;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileReceive {
    private static final String USAGE = "Usage: java FileReceive <host-ip> <host-port> [output-path]";
    private static final String KEY_DIRECTORY_PATH =
        System.getProperty("user.home") + File.separator + ".fileshare" + File.separator + "receive";

    public static void main(String[] args) throws Exception {
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        BufferedOutputStream fileWrite = null;
        try {
            logInfo("FileReceive invoked.");

            if (args == null || args.length < 2) {
                logError("Insufficient arguments were provided to FileReceive.");
                logInfo(USAGE);
                return;
            }

            String hostIp = args[0];
            int hostPort = Integer.parseInt(args[1]);
            logInfo("Receiver will attempt to connect to " + hostIp + ":" + hostPort + ".");

            try {
                socket = new Socket(hostIp, hostPort);
                logInfo("Socket connection established to sender. Local endpoint: " + socket.getLocalAddress().getHostAddress() + ":" + socket.getLocalPort() + ".");
            }
            catch (Exception e) {
                logException("The receiver could not connect to the sender at " + hostIp + ":" + hostPort + ".", e);
                System.err.println("Port does not exist!");
                return;
            }

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            logInfo("Binary network streams established. Starting key exchange.");

            logInfo("Loading or generating the local RSA public key.");
            PublicKey publicKey = getPublicKey();
            logInfo("Local public key is ready. Encoded key length: " + publicKey.getEncoded().length + " bytes.");

            logInfo("Loading or generating the local RSA private key.");
            PrivateKey privateKey = getPrivateKey();
            logInfo("Local private key is ready. Algorithm: " + privateKey.getAlgorithm() + ".");

            int clientKeySize = in.readInt();
            logInfo("Sender public key length received: " + clientKeySize + " bytes.");
            byte[] clientKeyBytes = new byte[clientKeySize];
            in.readFully(clientKeyBytes);
            logInfo("Sender public key bytes read completely from the socket.");

            KeyFactory factory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec clientSpec = new X509EncodedKeySpec(clientKeyBytes);
            PublicKey clientKey = factory.generatePublic(clientSpec);
            logInfo("Sender public key reconstructed successfully.");

            byte[] myKey = publicKey.getEncoded();
            out.writeInt(myKey.length);
            out.write(myKey);
            out.flush();
            logInfo("Local public key sent back to sender. Payload length: " + myKey.length + " bytes.");

            int sessionKeyLength = in.readInt();
            logInfo("Encrypted AES session key length received: " + sessionKeyLength + " bytes.");
            byte[] sessionKeyData = new byte[sessionKeyLength];
            in.readFully(sessionKeyData);
            logInfo("Encrypted AES session key bytes read completely.");

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] sessionKeyBytes = cipher.doFinal(sessionKeyData);
            SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
            logInfo("AES session key decrypted and reconstructed successfully. Raw key length: " + sessionKeyBytes.length + " bytes.");

            EncryptedData sessionAck = new EncryptedData();
            sessionAck.encrypt("SESSION_KEY_RECEIVED".getBytes(), sessionKey);
            logInfo("Encrypted acknowledgement prepared for sender verification.");

            out.writeInt(sessionAck.iv.length);
            out.write(sessionAck.iv);

            out.writeInt(sessionAck.encrypted.length);
            out.write(sessionAck.encrypted);
            out.flush();
            logInfo("Acknowledgement sent. IV length: " + sessionAck.iv.length + " bytes. Ciphertext length: " + sessionAck.encrypted.length + " bytes.");

            if (!in.readBoolean()) {
                logError("Sender reported acknowledgement verification failure.");
                throw new SecurityException("Acknowledgment failed at server side");
            }
            logInfo("Sender confirmed that the acknowledgement was accepted.");

            int nameIvSize = in.readInt();
            logInfo("Incoming encrypted file-name IV length: " + nameIvSize + " bytes.");
            byte[] nameIv = new byte[nameIvSize];
            in.readFully(nameIv);
            int nameDataSize = in.readInt();
            logInfo("Incoming encrypted file-name payload length: " + nameDataSize + " bytes.");
            byte[] nameData = new byte[nameDataSize];
            in.readFully(nameData);

            String fileName = new String(EncryptedData.decrypt(nameIv, nameData, sessionKey));
            logInfo("Received and decrypted sender file name: \"" + fileName + "\".");

            int fileIvSize = in.readInt();
            logInfo("Incoming encrypted file IV length: " + fileIvSize + " bytes.");
            byte[] fileIv = new byte[fileIvSize];
            in.readFully(fileIv);
            int fileDataSize = in.readInt();
            logInfo("Incoming encrypted file payload length: " + fileDataSize + " bytes.");
            byte[] fileData = new byte[fileDataSize];
            in.readFully(fileData);
            logInfo("Encrypted file payload received completely.");

            byte[] fileBytes = EncryptedData.decrypt(fileIv, fileData, sessionKey);
            logInfo("File payload decrypted successfully. Plaintext byte count: " + fileBytes.length + ".");

            File file = null;

            try {
                file = new File(args[2]);
                logInfo("Using caller-specified output path: " + file.getAbsolutePath());
            } catch (Exception e) {
                file = new File(fileName);
                logInfo("No explicit output path was usable. Falling back to sender-provided file name at path: " + file.getAbsolutePath());
            }

            if (file.exists()) {
                logError("Refusing to overwrite an existing file at " + file.getAbsolutePath() + ".");
                throw new FileAlreadyExistsException(fileName);
            }

            fileWrite = new BufferedOutputStream(new FileOutputStream(file));
            fileWrite.write(fileBytes);
            fileWrite.flush();
            logInfo("Decrypted file bytes written to disk successfully at " + file.getAbsolutePath() + ".");
            System.out.println("File transferred successfully!");
        }
        catch (ArrayIndexOutOfBoundsException e) {
            logException("A required command-line argument was missing while trying to receive a file.", e);
            throw e;
        }
        catch (NumberFormatException e) {
            logException("The provided host port could not be parsed as an integer.", e);
            throw e;
        }
        catch (UnknownHostException e) {
            logException("The supplied host name or IP address could not be resolved.", e);
            throw e;
        }
        catch (ConnectException e) {
            logException("A TCP connection to the sender could not be established.", e);
            throw e;
        }
        catch (NoRouteToHostException e) {
            logException("The network stack reported that there is no route to reach the sender host.", e);
            throw e;
        }
        catch (FileAlreadyExistsException e) {
            logException("The destination file already exists. The receiver intentionally avoids overwriting files.", e);
            throw e;
        }
        catch (FileNotFoundException e) {
            logException("A required file could not be opened. This may be a key file or the destination output path.", e);
            throw e;
        }
        catch (EOFException e) {
            logException("The sender closed the connection before the receiver finished reading the expected protocol data.", e);
            throw e;
        }
        catch (InvalidKeySpecException e) {
            logException("A stored RSA key file could not be parsed into a valid key specification.", e);
            throw e;
        }
        catch (InvalidKeyException e) {
            logException("A cryptographic key was rejected while decrypting or encrypting transfer material.", e);
            throw e;
        }
        catch (NoSuchAlgorithmException e) {
            logException("The required cryptographic algorithm was not available in the current Java runtime.", e);
            throw e;
        }
        catch (NoSuchPaddingException e) {
            logException("The required cipher padding scheme was not available in the current Java runtime.", e);
            throw e;
        }
        catch (BadPaddingException e) {
            logException("Decryption failed because the received cryptographic payload or padding was invalid.", e);
            throw e;
        }
        catch (IllegalBlockSizeException e) {
            logException("A cryptographic operation received data with an unexpected block size.", e);
            throw e;
        }
        catch (SocketException e) {
            logException("A socket-level network error interrupted the receiving workflow.", e);
            throw e;
        }
        catch (SecurityException e) {
            logException("A protocol security validation failed while receiving the file.", e);
            throw e;
        }
        catch (IOException e) {
            logException("A lower-level I/O error interrupted file access or network communication during receive.", e);
            throw e;
        }
        catch (Exception e) {
            logException("An unexpected exception escaped the receiving workflow.", e);
            throw e;
        }
        finally {
            closeQuietly(fileWrite, "output file stream");
            closeQuietly(in, "network input stream");
            closeQuietly(out, "network output stream");
            closeQuietly(socket, "connected socket");
        }
    }

    private static void generateAndStoreKeys() throws Exception {
        File keyDirectory = getKeyDirectory();
        ensureKeyDirectoryExists();
        logInfo("RSA key files were not found in " + keyDirectory.getAbsolutePath() + ". Generating a brand new 2048-bit RSA key pair.");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        logInfo("RSA key pair generated successfully.");

        File publicKeyFile = getPublicKeyFile();
        try (FileOutputStream fos = new FileOutputStream(publicKeyFile)) {
            fos.write(publicKey.getEncoded());
            logInfo("Public key written to " + publicKeyFile.getAbsolutePath() + ".");
        } catch (IOException e) {
            logException("Failed while writing the generated public key to disk.", e);
        }

        File privateKeyFile = getPrivateKeyFile();
        try (FileOutputStream fos = new FileOutputStream(privateKeyFile)) {
            fos.write(privateKey.getEncoded());
            logInfo("Private key written to " + privateKeyFile.getAbsolutePath() + ".");
        } catch (IOException e) {
            logException("Failed while writing the generated private key to disk.", e);
        }
    }

    private static PublicKey getPublicKey() throws Exception {
        File file = getPublicKeyFile();
        if (!file.exists()) {
            logInfo("Public key file does not exist yet. Triggering key generation.");
            generateAndStoreKeys();
        }

        logInfo("Reading public key bytes from " + file.getAbsolutePath() + ".");
        FileInputStream pubKey = new FileInputStream(file);
        byte[] publicKeyBytes = pubKey.readAllBytes();
        pubKey.close();
        logInfo("Public key read successfully. Byte length: " + publicKeyBytes.length + ".");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicSpec);
        return publicKey;
    }

    private static PrivateKey getPrivateKey() throws Exception {
        File priFile = getPrivateKeyFile();

        if (!priFile.exists()) {
            logInfo("Private key file does not exist yet. Triggering key generation.");
            generateAndStoreKeys();
        }

        logInfo("Reading private key bytes from " + priFile.getAbsolutePath() + ".");
        FileInputStream priKey = new FileInputStream(priFile);

        byte[] privateKeyBytes = priKey.readAllBytes();

        priKey.close();
        logInfo("Private key read successfully. Byte length: " + privateKeyBytes.length + ".");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);

        return privateKey;
    }

    private static File getKeyDirectory() {
        return new File(KEY_DIRECTORY_PATH);
    }

    private static File getPublicKeyFile() {
        return new File(getKeyDirectory(), "public.key");
    }

    private static File getPrivateKeyFile() {
        return new File(getKeyDirectory(), "private.key");
    }

    private static void ensureKeyDirectoryExists() throws IOException {
        File keyDirectory = getKeyDirectory();
        if (keyDirectory.exists()) {
            logInfo("Receiver key directory is available at " + keyDirectory.getAbsolutePath() + ".");
            return;
        }

        logInfo("Receiver key directory does not exist yet. Creating " + keyDirectory.getAbsolutePath() + ".");
        if (!keyDirectory.mkdirs() && !keyDirectory.exists()) {
            throw new IOException("Unable to create receiver key directory at " + keyDirectory.getAbsolutePath());
        }
        logInfo("Receiver key directory created successfully.");
    }

    private static void closeQuietly(Closeable closeable, String description) {
        if (closeable == null) {
            return;
        }

        try {
            closeable.close();
            logInfo("Closed " + description + ".");
        } catch (IOException e) {
            logException("Failed to close " + description + " cleanly.", e);
        }
    }

    private static void closeQuietly(Socket socket, String description) {
        if (socket == null) {
            return;
        }

        try {
            socket.close();
            logInfo("Closed " + description + ".");
        } catch (IOException e) {
            logException("Failed to close " + description + " cleanly.", e);
        }
    }

    private static void logInfo(String message) {
        System.out.println("[FileReceive][INFO] " + message);
    }

    private static void logError(String message) {
        System.err.println("[FileReceive][ERROR] " + message);
    }

    private static void logException(String context, Exception e) {
        logError(context);
        logError("Exception type: " + e.getClass().getName());
        logError("Exception message: " + (e.getMessage() == null ? "<no message supplied>" : e.getMessage()));
        e.printStackTrace(System.err);
    }
}
