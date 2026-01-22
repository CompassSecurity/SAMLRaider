package application;

import burp.BurpExtender;
import helpers.Compression;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.DataFormatException;

public class SamlMessageDecoder {

    public record DecodedSAMLMessage(
            String message,
            boolean isInflated,
            boolean isGZip) {
    }

    public static DecodedSAMLMessage getDecodedSAMLMessage(String message, boolean isWSSMessage, boolean isWSSUrlEncoded) {
        if (isWSSMessage) {
            if (isWSSUrlEncoded) {
                return new DecodedSAMLMessage(
                        BurpExtender.api.utilities().urlUtils().decode(message),
                        false, false);
            } else {
                return new DecodedSAMLMessage(message, false, false);
            }
        }

        String urlDecoded = BurpExtender.api.utilities().urlUtils().decode(message);
        urlDecoded = urlDecoded.replaceAll("\\R", "");
        byte[] base64Decoded = Base64.getDecoder().decode(urlDecoded);

        boolean isInflated = true;
        boolean isGZip = true;

        if (base64Decoded.length == 0) {
            isInflated = false;
            isGZip = false;
        } else {
            var compression = new Compression();
            try {
                byte[] inflated = compression.decompress(base64Decoded, true);
                return new DecodedSAMLMessage(new String(inflated, StandardCharsets.UTF_8), isInflated, isGZip);
            } catch (DataFormatException e) {
                isGZip = false;
            }
            try {
                byte[] inflated = compression.decompress(base64Decoded, false);
                return new DecodedSAMLMessage(new String(inflated, StandardCharsets.UTF_8), isInflated, isGZip);
            } catch (DataFormatException e) {
                isInflated = false;
            }
        }

        return new DecodedSAMLMessage(new String(base64Decoded, StandardCharsets.UTF_8), isInflated, isGZip);
    }

    private SamlMessageDecoder() {
        // static class
    }
}
