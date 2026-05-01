import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class FileSend {
    private static final String USAGE = "Usage: java FileSend <file-path>";
    private static final String KEY_DIRECTORY_PATH =
        System.getProperty("user.home") + File.separator + ".fileshare" + File.separator + "send";
    private static final TransferLogger LOGGER = new TransferLogger("SEND", 10);

    public static void main(String[] args) {
        FileInputStream file = null;
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        boolean failed = false;

        try {
            LOGGER.reset();
            logInfo("Starting send mode.");

            if (args == null || args.length == 0) {
                logError("Missing file path for send mode.");
                logInfo(USAGE);
                return;
            }

            File fileToSend = new File(args[0]);
            if (!fileToSend.exists()) {
                logError("Source file does not exist: " + fileToSend.getAbsolutePath());
                return;
            }

            logInfo("Ready to send " + fileToSend.getName() + " (" + fileToSend.length() + " bytes).");
            file = new FileInputStream(fileToSend);

            PublicKey publicKey = getPublicKey();
            getPrivateKey();
            logInfo("Sender identity is ready.");

            socket = getSocket();

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            byte[] myKey = publicKey.getEncoded();
            out.writeInt(myKey.length);
            out.write(myKey);
            out.flush();

            int clientKeySize = in.readInt();
            byte[] clientKeyBytes = new byte[clientKeySize];
            in.readFully(clientKeyBytes);

            KeyFactory factory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec clientSpec = new X509EncodedKeySpec(clientKeyBytes);
            PublicKey clientKey = factory.generatePublic(clientSpec);

            SecretKey sessionKey = generateAESKey();
            byte[] encryptedSessionKey = encryptSessionKey(sessionKey, clientKey);
            out.writeInt(encryptedSessionKey.length);
            out.write(encryptedSessionKey);
            out.flush();

            int ivSize = in.readInt();
            byte[] iv = new byte[ivSize];
            in.readFully(iv);

            int dataSize = in.readInt();
            byte[] data = new byte[dataSize];
            in.readFully(data);

            String msg = new String(EncryptedData.decrypt(iv, data, sessionKey));
            if (!msg.equals("SESSION_KEY_RECEIVED")) {
                out.writeBoolean(false);
                throw new SecurityException("Acknowledgement Failed");
            }

            out.writeBoolean(true);
            logSuccess("Secure handshake complete.");

            String name = fileToSend.getName();
            logInfo("Sending " + name + ".");

            EncryptedData fileName = new EncryptedData();
            fileName.encrypt(name.getBytes(), sessionKey);
            out.writeInt(fileName.iv.length);
            out.write(fileName.iv);

            out.writeInt(fileName.encrypted.length);
            out.write(fileName.encrypted);
            out.flush();

            byte[] fileData = file.readAllBytes();

            EncryptedData encryptedData = new EncryptedData();
            encryptedData.encrypt(fileData, sessionKey);

            out.writeInt(encryptedData.iv.length);
            out.write(encryptedData.iv);

            out.writeInt(encryptedData.encrypted.length);
            out.write(encryptedData.encrypted);
            out.flush();

            logSuccess("File transfer complete.");
        }
        catch (ArrayIndexOutOfBoundsException e) {
            failed = true;
            logException("Send mode is missing a required argument.", e);
        }
        catch (FileNotFoundException e) {
            failed = true;
            logException("Unable to open the source file or sender key files.", e);
        }
        catch (BindException e) {
            failed = true;
            logException("TCP port 2006 is already in use.", e);
        }
        catch (EOFException e) {
            failed = true;
            logException("The receiver disconnected before the protocol finished.", e);
        }
        catch (InvalidKeySpecException e) {
            failed = true;
            logException("Stored sender key files could not be parsed.", e);
        }
        catch (InvalidKeyException e) {
            failed = true;
            logException("A cryptographic key was rejected during send mode.", e);
        }
        catch (NoSuchAlgorithmException e) {
            failed = true;
            logException("This Java runtime is missing a required crypto algorithm.", e);
        }
        catch (NoSuchPaddingException e) {
            failed = true;
            logException("This Java runtime is missing a required cipher padding mode.", e);
        }
        catch (BadPaddingException e) {
            failed = true;
            logException("Handshake data could not be decrypted cleanly.", e);
        }
        catch (IllegalBlockSizeException e) {
            failed = true;
            logException("A cryptographic operation received an unexpected block size.", e);
        }
        catch (SocketException e) {
            failed = true;
            logException("A socket error interrupted send mode.", e);
        }
        catch (SecurityException e) {
            failed = true;
            logException("Protocol validation failed during send mode.", e);
        }
        catch (IOException e) {
            failed = true;
            logException("A file or network I/O error interrupted send mode.", e);
        }
        catch (Exception e) {
            failed = true;
            logException("An unexpected error escaped send mode.", e);
        }
        finally {
            closeQuietly(file, "input file stream");
            closeQuietly(in, "network input stream");
            closeQuietly(out, "network output stream");
            closeQuietly(socket, "connected socket");
        }

        if (failed) {
            System.exit(1);
        }
    }

    private static void generateAndStoreKeys() throws Exception {
        File keyDirectory = getKeyDirectory();
        ensureKeyDirectoryExists();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        File publicKeyFile = getPublicKeyFile();
        try (FileOutputStream fos = new FileOutputStream(publicKeyFile)) {
            fos.write(publicKey.getEncoded());
        } catch (IOException e) {
            logException("Failed while writing the generated public key to disk.", e);
        }

        File privateKeyFile = getPrivateKeyFile();
        try (FileOutputStream fos = new FileOutputStream(privateKeyFile)) {
            fos.write(privateKey.getEncoded());
        } catch (IOException e) {
            logException("Failed while writing the generated private key to disk.", e);
        }

        logSuccess("Created sender RSA keys in " + keyDirectory.getAbsolutePath() + ".");
    }

    private static PublicKey getPublicKey() throws Exception {
        File file = getPublicKeyFile();
        if (!file.exists()) {
            generateAndStoreKeys();
        }

        FileInputStream pubKey = new FileInputStream(file);
        byte[] publicKeyBytes = pubKey.readAllBytes();
        pubKey.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicSpec);
    }

    private static PrivateKey getPrivateKey() throws Exception {
        File priFile = getPrivateKeyFile();
        if (!priFile.exists()) {
            generateAndStoreKeys();
        }

        FileInputStream priKey = new FileInputStream(priFile);
        byte[] privateKeyBytes = priKey.readAllBytes();
        priKey.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateSpec);
    }

    private static Socket getSocket() throws Exception {
        ServerSocket socket = new ServerSocket(2006);
        logInfo("Waiting for a receiver on " + getLocalIP() + ":" + socket.getLocalPort() + ".");
        Socket acceptedSocket = socket.accept();
        logSuccess("Receiver connected.");
        socket.close();
        return acceptedSocket;
    }

    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static byte[] encryptSessionKey(SecretKey sessionKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(sessionKey.getEncoded());
    }

    private static String getLocalIP() throws Exception {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();
            if (!ni.isUp() || ni.isLoopback()) {
                continue;
            }

            Enumeration<InetAddress> addresses = ni.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress addr = addresses.nextElement();
                if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                    return addr.getHostAddress();
                }
            }
        }

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
        if (!keyDirectory.exists() && !keyDirectory.mkdirs() && !keyDirectory.exists()) {
            throw new IOException("Unable to create sender key directory at " + keyDirectory.getAbsolutePath());
        }
    }

    private static void closeQuietly(Closeable closeable, String description) {
        if (closeable == null) {
            return;
        }

        try {
            closeable.close();
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
        } catch (IOException e) {
            logException("Failed to close " + description + " cleanly.", e);
        }
    }

    private static void logInfo(String message) {
        LOGGER.info(message);
    }

    private static void logSuccess(String message) {
        LOGGER.success(message);
    }

    private static void logError(String message) {
        LOGGER.error(message);
    }

    private static void logException(String context, Exception e) {
        LOGGER.exception(context, e);
    }
}
