import java.io.PrintStream;

public final class TransferLogger {
    private static final String RESET = "\u001B[0m";
    private static final String BLUE = "\u001B[34m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String RED = "\u001B[31m";

    private final String label;
    private final int maxLines;
    private int linesPrinted;

    public TransferLogger(String label, int maxLines) {
        this.label = label;
        this.maxLines = maxLines;
    }

    public void reset() {
        linesPrinted = 0;
    }

    public void info(String message) {
        print(System.out, BLUE, "INFO", message);
    }

    public void success(String message) {
        print(System.out, GREEN, " OK ", message);
    }

    public void warn(String message) {
        print(System.out, YELLOW, "WARN", message);
    }

    public void error(String message) {
        print(System.err, RED, "ERR ", message);
    }

    public void exception(String context, Exception exception) {
        error(context);

        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            error("Cause: " + exception.getClass().getSimpleName());
            return;
        }

        error("Cause: " + exception.getClass().getSimpleName() + " - " + message);
    }

    private void print(PrintStream stream, String color, String level, String message) {
        if (linesPrinted >= maxLines) {
            return;
        }

        linesPrinted++;
        stream.println(color + "[" + label + "][" + level + "] " + message + RESET);
    }
}
