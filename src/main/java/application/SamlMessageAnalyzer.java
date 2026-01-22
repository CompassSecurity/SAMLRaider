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
            var samlResponseInBody = request.parameterValue(samlResponseParameterName, HttpParameterType.BODY);
            var samlResponseInUrl = request.parameterValue(samlResponseParameterName, HttpParameterType.URL);
            var samlRequestInBody = request.parameterValue(samlRequestParameterName, HttpParameterType.BODY);
            var samlRequestInUrl = request.parameterValue(samlRequestParameterName, HttpParameterType.URL);

            isSAMLMessage =
                    samlResponseInBody != null
                            || samlResponseInUrl != null
                            || samlRequestInBody != null
                            || samlRequestInUrl != null;

            if (isSAMLMessage) {
                isSAMLRequest = samlRequestInBody != null || samlRequestInUrl != null;
                isURLParam = samlResponseInUrl != null || samlRequestInUrl != null;

                String message =
                    Stream.of(samlResponseInBody, samlResponseInUrl, samlRequestInBody, samlRequestInUrl)
                        .filter(str -> str != null)
                        .findFirst()
                        .orElseThrow();

                var decodedSAMLMessage = SamlMessageDecoder.getDecodedSAMLMessage(message, isWSSMessage, isWSSUrlEncoded);
                isInflated = decodedSAMLMessage.isInflated();
                isGZip = decodedSAMLMessage.isGZip();
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

    private SamlMessageAnalyzer() {
        // static class
    }
}
