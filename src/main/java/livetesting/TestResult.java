package livetesting;

public record TestResult(boolean success,       String message, Throwable throwable) {
}
