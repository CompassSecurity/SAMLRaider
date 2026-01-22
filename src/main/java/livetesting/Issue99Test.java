package livetesting;

import application.CertificateTabController;
import application.SamlMessageAnalyzer;
import application.SamlMessageDecoder;
import application.SamlTabController;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import gui.CertificateTab;

public class Issue99Test {

    private final String rawRequest = """
            GET /idp/profile/SAML2/Redirect/SSO?SAMLRequest=fZJdT4MwFIb%2FCuk9FIjsoxkkuF24ZDoy0AtvTIGz0aS02FOc%2FnvZmDpvlvSub59z3iddIG9lx9LeNmoH7z2gdT5bqZCdL2LSG8U0R4FM8RaQ2Yrl6eOGhZ7POqOtrrQkTooIxgqtllph34LJwXyICp53m5g01nbIKOVcuDW02sOjsFXjVQ3NG1GWWoJtPERNT%2BSQZtu8IM5qWEUofoL%2BIXp1QUh9EMqzQ8aDuhf1CSbqjg4r7YWEC2kHtTBQWZrnW%2BKsVzF54z6PAvAn%2BzCo5zXsoZpGMAtmk7sohFlUDjHEHtYKLVc2JqEfTlw%2FcEO%2F8KdsOMH8lTjZpfm9ULVQh9uayjGE7KEoMnds9wIGz82GAEkWJ9nsPNhc6b%2BN5T%2FOSXLDMP4aXtCrKePIjj0N2PUq01JUX04qpT4uDXALMQkITcYn%2F79H8g0%3D&RelayState=ss%3Amem%3Ae81656ed0af8c914236f2fd6d31d250f162214ca23872fe3eea2194728edec10
            Host: uni-demo.login.test.eduid.ch
            Connection: keep-alive""";

    @TestOrder.Order(1)
    public TestResult isSAMLMessage() {
        try {
            var request = HttpRequest.httpRequest(rawRequest);
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var success = analysis.isSAMLMessage();
            return new TestResult(success, null, null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

    @TestOrder.Order(2)
    public TestResult isSAMLRequest() {
        try {
            var request = HttpRequest.httpRequest(rawRequest);
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var success = analysis.isSAMLMessage() && analysis.isSAMLRequest();
            return new TestResult(success, null, null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

    @TestOrder.Order(3)
    public TestResult canDecodeSAMLMessage() throws Exception {
        try {
            var request = HttpRequest.httpRequest(rawRequest);
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var samlRequest = request.parameterValue("SAMLRequest", HttpParameterType.URL);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(samlRequest, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            return new TestResult(true, decodedSamlMessage.message(), null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

    @TestOrder.Order(4)
    public TestResult isInflated() throws Exception {
        try {
            var request = HttpRequest.httpRequest(rawRequest);
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var samlRequest = request.parameterValue("SAMLRequest", HttpParameterType.URL);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(samlRequest, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            return new TestResult(analysis.isInflated() && decodedSamlMessage.isInflated(), null, null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

    @TestOrder.Order(5)
    public TestResult doesDeflate() throws Exception {
        try {
            var certificateTab = new CertificateTab();
            var certificateTabController = new CertificateTabController(certificateTab);
            var samlTabController = new SamlTabController(true, certificateTabController);
            var request = HttpRequest.httpRequest(rawRequest);
            var requestResponse = HttpRequestResponse.httpRequestResponse(request, null);
            samlTabController.setRequestResponse(requestResponse);
            var message = samlTabController.getEditorContents();
            var modifiedMessage = message.replace("<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://aai-demo.switch.ch/shibboleth</saml:Issuer>", "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://aai-demo.switch.ch.attacker.com/shibboleth</saml:Issuer>");
            samlTabController.setEditorContents(modifiedMessage);
            var modifiedRequest = samlTabController.getRequest();
            var actualSamlRequest = modifiedRequest.parameterValue("SAMLRequest", HttpParameterType.URL);
            var expectedSamlRequest = "fZJdT8IwFIb%2FytL7rdsiXw0jmXAhCQph6IU3pusOrLFrZ08n%2Bu%2FdGCpeSNK7vn3ec550irxSNUsbV%2BotvDWAzvuolEZ2ukhIYzUzHCUyzStA5gTL0vsVi4OQ1dY4I4wiXooI1kmj50ZjU4HNwL5LAY%2FbVUJK52pklHIu%2FQIqE%2BBROlEGoqRZKfPcKHBlgGhoR47pZp3tiLdoR5Gad9BfRKPPCGUOUgeuzQRQNLLoYLKoaTvSXio4k7ZQSAvC0SxbE2%2B5SMgLD%2FkggnC4j6NiUsAexGgA42g8vBnEMB7kbQyxgaVGx7VLSBzGQz%2BM%2FDjchSPWnmjyTLzNefNbqQupD9c15X0I2d1ut%2FH77Z7A4mmzNkBm0042OxXbC%2F3XsfzbOZn9bzjgznHxCjYQpqL4o3tKLyr7%2Fpo9tB3LxcYoKT69VClznFvgDhISETrrn%2Fz9K7Mv";
            return new TestResult(
                expectedSamlRequest.equals(actualSamlRequest),
                "Expected: %s\nGot: %s".formatted(expectedSamlRequest, actualSamlRequest),
                null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }
}
