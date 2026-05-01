import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Enumeration;

public class FileSend {
    private static final String USAGE = "Usage: java FileSend <file-path>";
    private static final String KEY_DIRECTORY_PATH =
        System.getProperty("user.home") + File.separator + ".fileshare" + File.separator + "send";

    public static void main(String[] args) throws Exception {
        FileInputStream file = null;
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;

        try {
            logInfo("FileSend invoked.");

            if (args == null || args.length == 0) {
                logError("No file path argument was provided to FileSend.");
                logInfo(USAGE);
                return;
            }

            File fileToSend = new File(args[0]);
            logInfo("Resolved input path: " + fileToSend.getAbsolutePath());
            logInfo("Checking whether the requested file exists and is readable.");
            if (!fileToSend.exists()) {
                System.err.println("Fatal!");
                System.err.println("File: \"" + args[0] + "\" does not exist!");
                logError("Input file lookup failed. The file does not exist at the supplied path.");
                return;
            }

            logInfo("Input file exists. File name: " + fileToSend.getName());
            logInfo("Input file size on disk: " + fileToSend.length() + " bytes.");
            file = new FileInputStream(fileToSend);
            logInfo("Input file stream opened successfully.");

            logInfo("Loading or generating the local RSA public key.");
            PublicKey publicKey = getPublicKey();
            logInfo("Local public key is ready. Encoded key length: " + publicKey.getEncoded().length + " bytes.");

            logInfo("Loading or generating the local RSA private key.");
            PrivateKey privateKey = getPrivateKey();
            logInfo("Local private key is ready. Algorithm: " + privateKey.getAlgorithm() + ".");

            logInfo("Creating server socket and waiting for the receiving peer to connect.");
            socket = getSocket();
            logInfo("A receiving peer connected from " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort() + ".");

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            logInfo("Binary network streams established. Starting key exchange.");

            byte[] myKey = publicKey.getEncoded();
            out.writeInt(myKey.length);
            out.write(myKey);
            out.flush();
            logInfo("Local public key sent to peer. Payload length: " + myKey.length + " bytes.");

            int clientKeySize = in.readInt();
            logInfo("Peer public key length received: " + clientKeySize + " bytes.");
            byte[] clientKeyBytes = new byte[clientKeySize];
            in.readFully(clientKeyBytes);
            logInfo("Peer public key bytes read completely from the socket.");

            KeyFactory factory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec clientSpec = new X509EncodedKeySpec(clientKeyBytes);
            PublicKey clientKey = factory.generatePublic(clientSpec);
            logInfo("Peer public key reconstructed successfully.");

            logInfo("Generating ephemeral AES session key for this transfer.");
            SecretKey sessionKey = generateAESKey();
            logInfo("AES session key generated. Raw key length: " + sessionKey.getEncoded().length + " bytes.");

            logInfo("Encrypting the session key with the peer public key.");
            byte[] encryptedSessionKey = encryptSessionKey(sessionKey, clientKey);
            out.writeInt(encryptedSessionKey.length);
            out.write(encryptedSessionKey);
            out.flush();
            logInfo("Encrypted session key transmitted. Ciphertext length: " + encryptedSessionKey.length + " bytes.");

            int ivSize = in.readInt();
            logInfo("Acknowledgement IV length announced by peer: " + ivSize + " bytes.");
            byte[] iv = new byte[ivSize];
            in.readFully(iv);
            logInfo("Acknowledgement IV fully received.");

            int dataSize = in.readInt();
            logInfo("Acknowledgement ciphertext length announced by peer: " + dataSize + " bytes.");
            byte[] data = new byte[dataSize];
            in.readFully(data);
            logInfo("Acknowledgement ciphertext fully received.");

            String msg = new String(EncryptedData.decrypt(iv, data, sessionKey));
            logInfo("Acknowledgement decrypted successfully. Message content: \"" + msg + "\".");

            if (!msg.equals("SESSION_KEY_RECEIVED")) {
                logError("Peer acknowledgement content did not match the expected confirmation token.");
                out.writeBoolean(false);
                throw new SecurityException("Acknowledgement Failed");
            }

            out.writeBoolean(true);
            logInfo("Acknowledgement verified. Positive confirmation sent to peer.");

            String name = fileToSend.getName();
            logInfo("Preparing to encrypt and send the file name: \"" + name + "\".");

            EncryptedData fileName = new EncryptedData();
            fileName.encrypt(name.getBytes(), sessionKey);
            out.writeInt(fileName.iv.length);
            out.write(fileName.iv);

            out.writeInt(fileName.encrypted.length);
            out.write(fileName.encrypted);
            out.flush();
            logInfo("Encrypted file name sent. IV length: " + fileName.iv.length + " bytes. Ciphertext length: " + fileName.encrypted.length + " bytes.");

            logInfo("Reading the entire file into memory before encryption.");
            byte[] fileData = file.readAllBytes();
            logInfo("File bytes read successfully. Plaintext byte count: " + fileData.length + ".");

            EncryptedData encryptedData = new EncryptedData();
            encryptedData.encrypt(fileData, sessionKey);
            logInfo("File content encrypted successfully. IV length: " + encryptedData.iv.length + " bytes. Ciphertext length: " + encryptedData.encrypted.length + " bytes.");

            out.writeInt(encryptedData.iv.length);
            out.write(encryptedData.iv);

            out.writeInt(encryptedData.encrypted.length);
            out.write(encryptedData.encrypted);

            out.flush();
            logInfo("Encrypted file payload flushed to peer successfully.");
            logInfo("FileSend finished its transfer workflow without protocol errors.");
        }
        catch (ArrayIndexOutOfBoundsException e) {
            logException("A required command-line argument was missing while trying to send a file.", e);
            throw e;
        }
        catch (FileNotFoundException e) {
            logException("A required file could not be opened. This may be the source file itself or a generated key file.", e);
            throw e;
        }
        catch (BindException e) {
            logException("The sender could not bind to TCP port 2006. Another process may already be using that port.", e);
            throw e;
        }
        catch (EOFException e) {
            logException("The remote peer closed the connection before the sender finished reading the expected protocol data.", e);
            throw e;
        }
        catch (InvalidKeySpecException e) {
            logException("A stored RSA key file could not be parsed into a valid key specification.", e);
            throw e;
        }
        catch (InvalidKeyException e) {
            logException("A cryptographic key was rejected while encrypting or decrypting transfer material.", e);
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
            logException("A socket-level network error interrupted the sending workflow.", e);
            throw e;
        }
        catch (SecurityException e) {
            logException("A protocol security validation failed while sending the file.", e);
            throw e;
        }
        catch (IOException e) {
            logException("A lower-level I/O error interrupted file access or network communication during send.", e);
            throw e;
        }
        catch (Exception e) {
            logException("An unexpected exception escaped the sending workflow.", e);
            throw e;
        }
        finally {
            closeQuietly(file, "input file stream");
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

    private static Socket getSocket() throws Exception {
        logInfo("Binding server socket to TCP port 2006.");
        ServerSocket socket = new ServerSocket(2006);
        System.out.println("Your IP: " + getLocalIP());
        System.out.println("Your PORT: " + socket.getLocalPort());
        logInfo("Server socket bound successfully. Waiting for an incoming receiver connection.");
        Socket acceptedSocket = socket.accept();
        logInfo("Incoming receiver accepted.");
        socket.close();
        logInfo("Listening server socket closed after accepting the single expected peer.");
        return acceptedSocket;
    }

    private static SecretKey generateAESKey() throws Exception {
        logInfo("Initializing AES key generator for a 256-bit session key.");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static byte[] encryptSessionKey(SecretKey sessionKey, PublicKey publicKey) throws Exception {
        logInfo("Encrypting AES session key with RSA/OAEP SHA-256.");
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(sessionKey.getEncoded());
    }

    private static String getLocalIP() throws Exception {
        logInfo("Inspecting local network interfaces to determine an outward-facing IPv4 address.");
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();

            if (!ni.isUp() || ni.isLoopback())
                continue;

            Enumeration<InetAddress> addresses = ni.getInetAddresses();

            while (addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();

                if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                    logInfo("Selected local IPv4 address " + addr.getHostAddress() + " from interface " + ni.getName() + ".");
                    return addr.getHostAddress();
                }
            }
        }
        logInfo("No outward-facing IPv4 address was found. Falling back to the label \"Unknown\".");
        return "Unknown";
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
            logInfo("Sender key directory is available at " + keyDirectory.getAbsolutePath() + ".");
            return;
        }

        logInfo("Sender key directory does not exist yet. Creating " + keyDirectory.getAbsolutePath() + ".");
        if (!keyDirectory.mkdirs() && !keyDirectory.exists()) {
            throw new IOException("Unable to create sender key directory at " + keyDirectory.getAbsolutePath());
        }
        logInfo("Sender key directory created successfully.");
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
        System.out.println("[FileSend][INFO] " + message);
    }

    private static void logError(String message) {
        System.err.println("[FileSend][ERROR] " + message);
    }

    private static void logException(String context, Exception e) {
        logError(context);
        logError("Exception type: " + e.getClass().getName());
        logError("Exception message: " + (e.getMessage() == null ? "<no message supplied>" : e.getMessage()));
        e.printStackTrace(System.err);
    }
}
