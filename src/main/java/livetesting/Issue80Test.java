package livetesting;

import application.SamlMessageAnalyzer;
import application.SamlMessageDecoder;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

public class Issue80Test {

    private final String rawRequest = """
            GET /sso/saml/authenticate?SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iX2Y5ZTY4YmYzN2NjNjU5M2FjMTQ3MmU4YmZkMjljYTcwNGU4ODJmNzViZCIgVmVyc2lvbj0iMi4wIiBQcm92aWRlck5hbWU9IkNob2NvIFNob3AiIElzc3VlSW5zdGFudD0iMjAyNC0xMC0zMVQwODo1OTo1OVoiIERlc3RpbmF0aW9uPSJodHRwczovL2U2YmZhNzEzLTUwOWMtNGIyMC1iODhmLTk1NmMxZDBiMTcwMy5pLnZ1bG4ubGFuZC9zc28vc2FtbCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vZTZiZmE3MTMtNTA5Yy00YjIwLWI4OGYtOTU2YzFkMGIxNzAzLmkudnVsbi5sYW5kL2FwaS9hY3MiPjxzYW1sOklzc3Vlcj5odHRwczovL2U2YmZhNzEzLTUwOWMtNGIyMC1iODhmLTk1NmMxZDBiMTcwMy5pLnZ1bG4ubGFuZDwvc2FtbDpJc3N1ZXI%2BPHNhbWxwOk5hbWVJRFBvbGljeSBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyIgQWxsb3dDcmVhdGU9InRydWUiLz48c2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249ImV4YWN0Ij48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWxwOlJlcXVlc3RlZEF1dGhuQ29udGV4dD48L3NhbWxwOkF1dGhuUmVxdWVzdD4%3D HTTP/2
            Host: e6bfa713-509c-4b20-b88f-956c1d0b1703.i.vuln.land
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
            var body = request.parameterValue("SAMLRequest", HttpParameterType.URL);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(body, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            return new TestResult(true, decodedSamlMessage.message(), null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }
}
