import java.util.Arrays;

public class FileShare {
    private static final String VERSION = "FileShare 1.0.0";

    public static void main(String[] args) throws Exception {
        try {
            if (args == null || args.length == 0) {
                printUsage();
                return;
            }

            String mode = args[0];

            if (isHelpCommand(mode)) {
                printUsage();
                return;
            }

            if (isVersionCommand(mode)) {
                printVersion();
                return;
            }

            if (isAuthorCommand(mode)) {
                printAuthor();
                return;
            }

            if (mode.equals("send")) {
                if (args.length < 2) {
                    System.err.println("[FileShare][ERROR] Missing required argument for send mode.");
                    System.err.println("[FileShare][ERROR] The send mode requires the path to the file that should be hosted and transmitted.");
                    printSendUsage();
                    return;
                }

                FileSend.main(Arrays.copyOfRange(args, 1, args.length));
            }
            else if (mode.equals("receive")) {
                if (args.length < 3) {
                    System.err.println("[FileShare][ERROR] Missing required arguments for receive mode.");
                    System.err.println("[FileShare][ERROR] The receive mode requires a host IP or host name and a numeric TCP port.");
                    printReceiveUsage();
                    return;
                }

                FileReceive.main(Arrays.copyOfRange(args, 1, args.length));
            }
            else {
                System.err.println("[FileShare][ERROR] Invalid mode: " + mode);
                System.err.println("[FileShare][ERROR] Supported modes are: send, receive, --help, --version, --who-did-this.");
                printUsage();
            }
        }
        catch (NumberFormatException e) {
            logException("A numeric argument, most likely the network port for receive mode, could not be parsed as an integer.", e);
            throw e;
        }
        catch (SecurityException e) {
            logException("The delegated send or receive operation reported a protocol or access-security failure.", e);
            throw e;
        }
        catch (ArrayIndexOutOfBoundsException e) {
            logException("A required command-line argument was missing while dispatching the requested mode.", e);
            throw e;
        }
        catch (Exception e) {
            logException("An unexpected exception escaped the FileShare command dispatcher.", e);
            throw e;
        }
    }

    private static boolean isHelpCommand(String value) {
        return value.equals("--help") || value.equals("-h") || value.equals("help");
    }

    private static boolean isVersionCommand(String value) {
        return value.equals("--version") || value.equals("-v") || value.equals("version");
    }

    private static boolean isAuthorCommand(String value) {
        return value.equals("--who-did-this");
    }

    private static void printVersion() {
        System.out.println(VERSION);
        System.out.println("Command dispatcher for encrypted peer-to-peer file sharing.");
        System.out.println("Transport model: one sender listens on port 2006 and one receiver connects to that host.");
    }

    private static void printAuthor() {
        System.out.println("Hari Hara Sudhan");
    }

    private static void printUsage() {
        System.out.println("FileShare Command-Line Interface");
        System.out.println();
        System.out.println("Purpose:");
        System.out.println("  Launch the encrypted file transfer workflow in either sender mode or receiver mode.");
        System.out.println("  The transfer protocol exchanges RSA public keys, delivers an AES session key securely,");
        System.out.println("  and then transmits the file name and file contents through AES-encrypted payloads.");
        System.out.println();
        System.out.println("Primary Syntax:");
        System.out.println("  java FileShare <mode> [mode-arguments]");
        System.out.println();
        System.out.println("Supported Modes:");
        System.out.println("  send       Host a file locally, wait for one receiver connection, and send the encrypted file.");
        System.out.println("  receive    Connect to an existing sender, complete the key exchange, and write the decrypted file locally.");
        System.out.println();
        System.out.println("Global Flags:");
        System.out.println("  --help, -h, help        Show this detailed help text.");
        System.out.println("  --version, -v, version  Show the current CLI version and high-level behavior summary.");
        System.out.println("  --who-did-this          Show the author name for this project.");
        System.out.println();
        System.out.println("Send Mode Syntax:");
        System.out.println("  java FileShare send <file-path>");
        System.out.println("  <file-path> must point to an existing local file that the sender can read.");
        System.out.println("  The sender will listen on TCP port 2006, print its detected IP address and port,");
        System.out.println("  and then wait until exactly one receiver connects.");
        System.out.println();
        System.out.println("Receive Mode Syntax:");
        System.out.println("  java FileShare receive <host-ip> <host-port> [output-path]");
        System.out.println("  <host-ip> can be an IPv4 address or host name that resolves to the sender.");
        System.out.println("  <host-port> must be the numeric port printed by the sender.");
        System.out.println("  [output-path] is optional. If omitted, the original sender file name is used locally.");
        System.out.println("  If the destination file already exists, the receiver aborts instead of overwriting it.");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java FileShare --help");
        System.out.println("  java FileShare --version");
        System.out.println("  java FileShare --who-did-this");
        System.out.println("  java FileShare send /Users/example/Documents/archive.zip");
        System.out.println("  java FileShare receive 192.168.1.20 2006");
        System.out.println("  java FileShare receive 192.168.1.20 2006 /Users/example/Downloads/archive-copy.zip");
        System.out.println();
        System.out.println("Operational Notes:");
        System.out.println("  The sender stores RSA key files under ~/.fileshare/send/public.key and ~/.fileshare/send/private.key by default.");
        System.out.println("  The receiver stores RSA key files under ~/.fileshare/receive/public.key and ~/.fileshare/receive/private.key by default.");
        System.out.println("  If those key files are missing, new keys are generated automatically before transfer continues.");
        System.out.println("  Detailed runtime logs are printed directly by FileSend and FileReceive for troubleshooting.");
        System.out.println("  This dispatcher validates arguments and forwards execution to the requested mode without changing the transfer protocol.");
        System.out.println();
        System.out.println("Mode-Specific Help:");
        System.out.println("  Run one of the commands below to focus on a single mode:");
        System.out.println("  java FileShare send <file-path>");
        System.out.println("  java FileShare receive <host-ip> <host-port> [output-path]");
    }

    private static void printSendUsage() {
        System.out.println("Send Mode Help");
        System.out.println("  Syntax: java FileShare send <file-path>");
        System.out.println("  Behavior: Opens the specified file, loads or generates RSA keys, listens on port 2006,");
        System.out.println("            performs the secure key exchange, and transmits the encrypted file name and contents.");
        System.out.println("  Requirement: <file-path> must exist and be readable.");
        System.out.println("  Example: java FileShare send /Users/example/Desktop/report.pdf");
    }

    private static void printReceiveUsage() {
        System.out.println("Receive Mode Help");
        System.out.println("  Syntax: java FileShare receive <host-ip> <host-port> [output-path]");
        System.out.println("  Behavior: Connects to the sender, exchanges public keys, decrypts the AES session key,");
        System.out.println("            acknowledges receipt, downloads the encrypted file metadata and payload,");
        System.out.println("            decrypts everything locally, and writes the result to disk.");
        System.out.println("  Requirement: <host-port> must be a valid integer and [output-path] must not already exist.");
        System.out.println("  Example: java FileShare receive 192.168.1.20 2006 /Users/example/Downloads/report.pdf");
    }

    private static void logException(String context, Exception e) {
        System.err.println("[FileShare][ERROR] " + context);
        System.err.println("[FileShare][ERROR] Exception type: " + e.getClass().getName());
        System.err.println("[FileShare][ERROR] Exception message: " + (e.getMessage() == null ? "<no message supplied>" : e.getMessage()));
        e.printStackTrace(System.err);
    }
}
