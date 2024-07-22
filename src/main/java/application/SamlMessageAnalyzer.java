package application;

import burp.BurpExtender;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import helpers.XMLHelpers;
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
            boolean isGZip) {
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
            String requestParameter;
            requestParameter = request.parameterValue(samlResponseParameterName, HttpParameterType.BODY);
            if (requestParameter != null) {
                isSAMLMessage = true;
            }
            requestParameter = request.parameterValue(samlRequestParameterName, HttpParameterType.BODY);
            if (requestParameter != null) {
                isSAMLRequest = true;
                isSAMLMessage = true;
            }
        }

        return new SamlMessageAnalysisResult(
                isSAMLMessage,
                isSOAPMessage,
                isWSSUrlEncoded,
                isWSSMessage,
                isSAMLRequest,
                isInflated,
                isGZip);
    }

    private SamlMessageAnalyzer() {
        // static class
    }

}
