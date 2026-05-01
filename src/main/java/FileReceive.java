import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.FileAlreadyExistsException;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FileReceive {
    private static final String USAGE = "Usage: java FileReceive <host-ip> <host-port> [output-path]";
    private static final String KEY_DIRECTORY_PATH =
        System.getProperty("user.home") + File.separator + ".fileshare" + File.separator + "receive";
    private static final TransferLogger LOGGER = new TransferLogger("RECV", 10);

    public static void main(String[] args) {
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        BufferedOutputStream fileWrite = null;
        boolean failed = false;

        try {
            LOGGER.reset();
            logInfo("Starting receive mode.");

            if (args == null || args.length < 2) {
                logError("Missing host or port for receive mode.");
                logInfo(USAGE);
                return;
            }

            String hostIp = args[0];
            int hostPort = Integer.parseInt(args[1]);
            logInfo("Connecting to " + hostIp + ":" + hostPort + ".");

            socket = new Socket(hostIp, hostPort);
            logSuccess("Connected to sender.");

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            PublicKey publicKey = getPublicKey();
            PrivateKey privateKey = getPrivateKey();
            logInfo("Receiver identity is ready.");

            int clientKeySize = in.readInt();
            byte[] clientKeyBytes = new byte[clientKeySize];
            in.readFully(clientKeyBytes);

            KeyFactory factory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec clientSpec = new X509EncodedKeySpec(clientKeyBytes);
            factory.generatePublic(clientSpec);

            byte[] myKey = publicKey.getEncoded();
            out.writeInt(myKey.length);
            out.write(myKey);
            out.flush();

            int sessionKeyLength = in.readInt();
            byte[] sessionKeyData = new byte[sessionKeyLength];
            in.readFully(sessionKeyData);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] sessionKeyBytes = cipher.doFinal(sessionKeyData);
            SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

            EncryptedData sessionAck = new EncryptedData();
            sessionAck.encrypt("SESSION_KEY_RECEIVED".getBytes(), sessionKey);

            out.writeInt(sessionAck.iv.length);
            out.write(sessionAck.iv);
            out.writeInt(sessionAck.encrypted.length);
            out.write(sessionAck.encrypted);
            out.flush();

            if (!in.readBoolean()) {
                throw new SecurityException("Acknowledgment failed at server side");
            }

            logSuccess("Secure handshake complete.");

            int nameIvSize = in.readInt();
            byte[] nameIv = new byte[nameIvSize];
            in.readFully(nameIv);

            int nameDataSize = in.readInt();
            byte[] nameData = new byte[nameDataSize];
            in.readFully(nameData);

            String fileName = new String(EncryptedData.decrypt(nameIv, nameData, sessionKey));
            logInfo("Receiving " + fileName + ".");

            int fileIvSize = in.readInt();
            byte[] fileIv = new byte[fileIvSize];
            in.readFully(fileIv);

            int fileDataSize = in.readInt();
            byte[] fileData = new byte[fileDataSize];
            in.readFully(fileData);

            byte[] fileBytes = EncryptedData.decrypt(fileIv, fileData, sessionKey);

            File file;
            try {
                file = new File(args[2]);
            } catch (Exception e) {
                file = new File(fileName);
            }

            logInfo("Saving to " + file.getAbsolutePath() + ".");

            if (file.exists()) {
                throw new FileAlreadyExistsException(fileName);
            }

            fileWrite = new BufferedOutputStream(new FileOutputStream(file));
            fileWrite.write(fileBytes);
            fileWrite.flush();

            logSuccess("File transfer complete.");
        }
        catch (ArrayIndexOutOfBoundsException e) {
            failed = true;
            logException("Receive mode is missing a required argument.", e);
        }
        catch (NumberFormatException e) {
            failed = true;
            logException("The provided port is not a valid integer.", e);
        }
        catch (UnknownHostException e) {
            failed = true;
            logException("The supplied host name or IP address could not be resolved.", e);
        }
        catch (ConnectException e) {
            failed = true;
            logException("A TCP connection to the sender could not be established.", e);
        }
        catch (NoRouteToHostException e) {
            failed = true;
            logException("The network stack could not reach the sender host.", e);
        }
        catch (FileAlreadyExistsException e) {
            failed = true;
            logException("The destination file already exists. Receive mode will not overwrite it.", e);
        }
        catch (FileNotFoundException e) {
            failed = true;
            logException("A key file or destination path could not be opened.", e);
        }
        catch (EOFException e) {
            failed = true;
            logException("The sender disconnected before the protocol finished.", e);
        }
        catch (InvalidKeySpecException e) {
            failed = true;
            logException("Stored receiver key files could not be parsed.", e);
        }
        catch (InvalidKeyException e) {
            failed = true;
            logException("A cryptographic key was rejected during receive mode.", e);
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
            logException("Handshake or file data could not be decrypted cleanly.", e);
        }
        catch (IllegalBlockSizeException e) {
            failed = true;
            logException("A cryptographic operation received an unexpected block size.", e);
        }
        catch (SocketException e) {
            failed = true;
            logException("A socket error interrupted receive mode.", e);
        }
        catch (SecurityException e) {
            failed = true;
            logException("Protocol validation failed during receive mode.", e);
        }
        catch (IOException e) {
            failed = true;
            logException("A file or network I/O error interrupted receive mode.", e);
        }
        catch (Exception e) {
            failed = true;
            logException("An unexpected error escaped receive mode.", e);
        }
        finally {
            closeQuietly(fileWrite, "output file stream");
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

        logSuccess("Created receiver RSA keys in " + keyDirectory.getAbsolutePath() + ".");
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
            throw new IOException("Unable to create receiver key directory at " + keyDirectory.getAbsolutePath());
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
