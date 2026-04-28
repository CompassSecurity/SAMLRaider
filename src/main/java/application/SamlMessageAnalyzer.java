package application;

import burp.BurpExtender;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import helpers.XMLHelpers;

import java.util.stream.Stream;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class SamlMessageAnalyzer {

    public record SamlMessageAnalysisResult(
            boolean isSAMLMessage,
            boolean isSOAPMessage,
            boolean isWSSUrlEncoded,
            boolean isWSSMessage,
            boolean isSAMLRequest,
            boolean isInflated,
            boolean isGZip,
            boolean isURLParam) {
    }

    public static SamlMessageAnalysisResult analyze(
            HttpRequest request,
            String samlRequestParameterName,
            String samlResponseParameterName) {

        var isSOAPMessage = false;
        var isWSSUrlEncoded = false;
        var isWSSMessage = false;
        var isSAMLMessage = false;
        var isSAMLRequest = false;
        var isInflated = false;
        var isGZip = false;
        var isURLParam = false;

        var xmlHelpers = new XMLHelpers();
        if (request.contentType() == ContentType.XML) {
            isSOAPMessage = true;
            try {
                String soapMessage = request.bodyToString();
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                isSAMLMessage = xmlHelpers.getAssertions(document).getLength() != 0 || xmlHelpers.getEncryptedAssertions(document).getLength() != 0;
            } catch (SAXException e) {
                BurpExtender.api.logging().logToError(e);
            }
        }
        // WSS Security
        else if (request.hasParameter("wresult", HttpParameterType.BODY)) {
            try {
                isWSSUrlEncoded = request.contentType() == ContentType.URL_ENCODED;
                isWSSMessage = true;
                String parameterValue = request.parameterValue("wresult", HttpParameterType.BODY);
                var decodedSAMLMessage = SamlMessageDecoder.getDecodedSAMLMessage(parameterValue, isWSSMessage, isWSSUrlEncoded);
                isInflated = decodedSAMLMessage.isInflated();
                isGZip = decodedSAMLMessage.isGZip();
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(decodedSAMLMessage.message());
                isSAMLMessage = xmlHelpers.getAssertions(document).getLength() != 0 || xmlHelpers.getEncryptedAssertions(document).getLength() != 0;
            } catch (SAXException e) {
                BurpExtender.api.logging().logToError(e);
            }
        } else {
            var log = BurpExtender.api.logging();
            log.logToOutput("[SAML Raider] analyze() — contentType=" + request.contentType()
                    + " body[0..80]=" + request.bodyToString().replace("\n","").replace("\r","").substring(0, Math.min(80, request.bodyToString().length())));

            var samlResponseInBody = extractParameterValue(request, samlResponseParameterName, HttpParameterType.BODY);
            var samlResponseInUrl  = request.parameterValue(samlResponseParameterName, HttpParameterType.URL);
            var samlRequestInBody  = extractParameterValue(request, samlRequestParameterName, HttpParameterType.BODY);
            var samlRequestInUrl   = request.parameterValue(samlRequestParameterName, HttpParameterType.URL);

            log.logToOutput("[SAML Raider] responseInBody=" + (samlResponseInBody != null ? samlResponseInBody.substring(0, Math.min(40, samlResponseInBody.length())) : "null")
                    + " requestInBody=" + (samlRequestInBody != null ? samlRequestInBody.substring(0, Math.min(40, samlRequestInBody.length())) : "null"));

            isSAMLMessage =
                    samlResponseInBody != null
                            || samlResponseInUrl != null
                            || samlRequestInBody != null
                            || samlRequestInUrl != null;

            log.logToOutput("[SAML Raider] isSAMLMessage=" + isSAMLMessage);

            if (isSAMLMessage) {
                isSAMLRequest = samlRequestInBody != null || samlRequestInUrl != null;
                isURLParam = samlResponseInUrl != null || samlRequestInUrl != null;

                String message =
                    Stream.<String>of(samlResponseInBody, samlResponseInUrl, samlRequestInBody, samlRequestInUrl)
                        .filter(str -> str != null)
                        .findFirst()
                        .orElseThrow();

                try {
                    var decodedSAMLMessage = SamlMessageDecoder.getDecodedSAMLMessage(message, isWSSMessage, isWSSUrlEncoded);
                    isInflated = decodedSAMLMessage.isInflated();
                    isGZip = decodedSAMLMessage.isGZip();
                } catch (Exception e) {
                    // Decode failure doesn't hide the tab
                    BurpExtender.api.logging().logToError(e);
                }
            }
        }

        return new SamlMessageAnalysisResult(
                isSAMLMessage,
                isSOAPMessage,
                isWSSUrlEncoded,
                isWSSMessage,
                isSAMLRequest,
                isInflated,
                isGZip,
                isURLParam);
    }

    /**
     * Returns the value of a body parameter, falling back to a raw-body scan when Burp's
     * URL-param parser returns null (e.g. because Hackvertor tags containing literal '<' chars
     * are present in the body and break standard URL-encoded parsing).
     */
    public static String extractParameterValue(HttpRequest request, String paramName, HttpParameterType type) {
        String value = request.parameterValue(paramName, type);
        if (value != null) return value;

        if (type != HttpParameterType.BODY) return null;

        // Strip Hackvertor tags then scan the raw body for name=value
        String rawBody = request.bodyToString().replaceAll("</?@[^>]+>", "");
        String marker = paramName + "=";
        int idx = rawBody.indexOf(marker);
        if (idx < 0) return null;
        String val = rawBody.substring(idx + marker.length());
        int amp = val.indexOf('&');
        return amp >= 0 ? val.substring(0, amp) : val;
    }

    private SamlMessageAnalyzer() {
        // static class
    }
}
