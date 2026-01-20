package application;

import helpers.Compression;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SamlMessageEncoder {

    public static String getEncodedSAMLMessage(
            String message,
            boolean isWSSMessage,
            boolean isWSSUrlEncoded,
            boolean isInflated,
            boolean isGZip) {

        if (isWSSMessage) {
            if (isWSSUrlEncoded) {
                return URLEncoder.encode(message, StandardCharsets.UTF_8);
            } else {
                return message;
            }
        }

        byte[] byteMessage = message.getBytes(StandardCharsets.UTF_8);

        if (isInflated) {
            var compression = new Compression();
            byteMessage = compression.compress(byteMessage, isGZip);
        }

        String base64Encoded = Base64.getEncoder().encodeToString(byteMessage);
        return URLEncoder.encode(base64Encoded, StandardCharsets.UTF_8);
    }

    private SamlMessageEncoder() {
        // static class
    }
}
