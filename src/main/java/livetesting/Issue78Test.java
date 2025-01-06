package livetesting;

import application.CertificateTabController;
import application.SamlMessageAnalyzer;
import application.SamlMessageDecoder;
import application.SamlTabController;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import gui.CertificateTab;

public class Issue78Test {

    private final String rawRequest = """
            POST /api/oauth/saml HTTP/1.1
            Host: sso.eu.boxyhq.com
            Content-Length: 13516
            Cache-Control: max-age=0
            Accept-Language: en-GB
            Upgrade-Insecure-Requests: 1
            Origin: https://mocksaml.com
            Content-Type: application/x-www-form-urlencoded
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36
            Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
            Referer: https://mocksaml.com/
            Accept-Encoding: gzip, deflate, br
            Priority: u=0, i
            Connection: keep-alive
            
            SAMLResponse=PHNhbWxwOlJlc3BvbnNlIElEPV9mYjVhZjBmMC1mMmI2LTQ4YjctYTNmZS02ZTMwYTBjOGM3ZDEgVmVyc2lvbj0yLjAgSXNzdWVJbnN0YW50PTIwMjQtMDktMThUMTE6MTQ6NDMuMDUwWiBEZXN0aW5hdGlvbj1odHRwczovL2Rlc3RpbmF0aW9uLyBJblJlc3BvbnNlVG89T05FTE9HSU5fY2RiZjg1Mzg3NmE4MzcyZDQwYjkzNDFhNGY5NzE0NDJmMDhiNDEzZCB4bWxuczpzYW1scD11cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2w%2BPElzc3VlciB4bWxucz11cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIxZWE5MTZiLWQ5MmYtNDdmMC1iZDY1LWM2N2I5NzJlNjVhZS88L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPXVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2Vzcy8%2BPC9zYW1scDpTdGF0dXM%2BPEFzc2VydGlvbiBJRD1fZTY4ZmMyNDQtZDUxNy00ZWNiLTk5OGYtNzhkYzBmNDI3YTAwIElzc3VlSW5zdGFudD0yMDI0LTA5LTE4VDExOjE0OjQzLjA0NlogVmVyc2lvbj0yLjAgeG1sbnM9dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbj48SXNzdWVyPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIxZWE5MTZiLWQ5MmYtNDdmMC1iZDY1LWM2N2I5NzJlNjVhZS88L0lzc3Vlcj48U2lnbmF0dXJlIHhtbG5zPWh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyM%2BPFNpZ25lZEluZm8%2BPENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPWh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIy8%2BPFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09aHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1Ni8%2BPFJlZmVyZW5jZSBVUkk9I19lNjhmYzI0NC1kNTE3LTRlY2ItOTk4Zi03OGRjMGY0MjdhMDA%2BPFRyYW5zZm9ybXM%2BPFRyYW5zZm9ybSBBbGdvcml0aG09aHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUvPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPWh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIy8%2BPC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPWh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1Ni8%2BPERpZ2VzdFZhbHVlPlY4UFg3Z1hHSCBXYkZGYkhzYndULzJ0cjlZV0hVcW1BU2RPRCB0Y2lLVnc9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8%2BPFNpZ25hdHVyZVZhbHVlPnIxRFcwdUlERkJubHlzS0tISUE5VFlZRjFxRDd1VDdTa292Q1JrRWdlbm9ZWG1NVGQvWEtpYUlWNFgxTElsSTBzVjBxajZGTlV0dTFZR295UTNKWEQ2QTYxcXd2SUFJeUt0dmVRVGNaOUg3MTlEVTZEcHggZnQydGNQNm0yRDJCcGg5QlcyVklRMXFPY3BpQTlNU3pSSmV0eDZQaExpNnhaeDVncWxJRnp5Q0dnVGpFR3cwQW5scTZvMnJISVZFcGRlVGhJdWU0RndmYU51NGJybjRnMUloeFJRRC9jT1ZHUzVCcUNHakFwcExzSWlRc1FWT2IgL0RmRlBUeUxBSlBteFNyWGtXZGRnenBaTFhwUTZZTzFxcGV5MVRpVWZGQ3dZRVljc3J2RHQxM0h0a0d2cm44MjBpS0hIT0c4a2FkQTB3SmtBRXA3d0xYQmM4Wmo4YTZrUT09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE%2BPFg1MDlDZXJ0aWZpY2F0ZT5NSUlDOERDQ0FkaWdBd0lCQWdJUVVOWVNjVlpwIGFGQ2g4VCB3d0Y4UlRBTkJna3Foa2lHOXcwQkFRc0ZBREEwTVRJd01BWURWUVFERXlsTmFXTnliM052Wm5RZ1FYcDFjbVVnUm1Wa1pYSmhkR1ZrSUZOVFR5QkRaWEowYVdacFkyRjBaVEFlRncweU5EQTVNRE14TkRBek1ERmFGdzB5TnpBNU1ETXhOREF6TURCYU1EUXhNakF3QmdOVkJBTVRLVTFwWTNKdmMyOW1kQ0JCZW5WeVpTQkdaV1JsY21GMFpXUWdVMU5QSUVObGNuUnBabWxqWVhSbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBNDZMb25hRnZaeFFCR1BvM0pObi83U0FSRHBhRCBWcndacEszRzN6eVhQeDZ2aXdNMDR0UDM4NUJSZTJpbHlvNmx2IFEyNS9MblRXOWhNdFl1aGNEenNEbzBHYkpMWG5jeEtWaGFrb2owR1JUemFMNlhpdCBOZ2RDRkUzOGZaVG9kOGk4clFWMHpuZ2Z1IHNoanFyVXVxMVA2eElzcUEgT2xEbmZ0UDl3QzRYaXpZTDVyckpuenh5YUN3MDExaS9yeDI0TnFEOGtGZlRWcXQxTXRtQU1XR1ZaVGJzS3k1d1hXWWYgZHp2TVVZbDZWSHZGcWUwaDZnaEMvU3hVbnRUY3lRVGVRbFhIN2JYZEs2ZlRzNXV3V2ZnVGJSWmJrNDN6T0tyZmc2UUFZUVBQaWFuWDA4cFZ5RjZrRlhUcGhVenpLNWF2VjRVRUN0U0xwbzZSQkdXTGhRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCOTdSclk1ZHk0dHpQNlhUU1g1Nm1WQkdZL043M28vWklvRjFMU1dJbGZCVnFNZFkyOUVKYlhFSWhhdFY3SmcvRzFPQ1RLRG94Wm9NTzNlMVk2THlMZzE4MDhaSWpnQiBwZC9uMlN4QmZpaUhmdGNRWjIgWnNJUVpyWjJjY05xYk9RaktwQ081WXdaVmhWUkdNQTA5UkxhMmovUlYxZ1A3WVhOR2d2YWpRYXI5MmkyeDljV2EgLzV2SThWUUZ4clpTUUZFM0JnUDIgeTAwSjQ2RS9HaGtLaG1pMExPIEg4T2Q0eFFhdmxOeXo2MnVKMmJmYVZ5dzR5U2V6WnR1RTM3UnQgb0hJNDBzV01vVTg4QkZ0ckExTVczOVlQaiBUSGZONEo3MXVXWSBqOWdKWDZWOHNPMFF6dWplV2xndWg2dFZrb3lqUEZ4bXFXIGFIcWlVRTNiY208L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48U3ViamVjdD48TmFtZUlEIEZvcm1hdD11cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3M%2Bbm9ib2R5QG5vd2hlcmUuY29tPC9OYW1lSUQ%2BPFN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPXVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXI%2BPFN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz1PTkVMT0dJTl9jZGJmODUzODc2YTgzNzJkNDBiOTM0MWE0Zjk3MTQ0MmYwOGI0MTNkIE5vdE9uT3JBZnRlcj0yMDI0LTA5LTE4VDEyOjE0OjQyLjkzNFogUmVjaXBpZW50PWh0dHBzOi8vZGVzdGluYXRpb24vLz48L1N1YmplY3RDb25maXJtYXRpb24%2BPC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0yMDI0LTA5LTE4VDExOjA5OjQyLjkzNFogTm90T25PckFmdGVyPTIwMjQtMDktMThUMTI6MTQ6NDIuOTM0Wj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U%2BaHR0cHM6Ly9kZXN0aW5hdGlvbi88L0F1ZGllbmNlPjwvQXVkaWVuY2VSZXN0cmljdGlvbj48L0NvbmRpdGlvbnM%2BPEF0dHJpYnV0ZVN0YXRlbWVudD48QXR0cmlidXRlIE5hbWU9aHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvdGVuYW50aWQ%2BPEF0dHJpYnV0ZVZhbHVlPjIxZWE5MTZiLWQ5MmYtNDdmMC1iZDY1LWM2N2I5NzJlNjVhZTwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPWh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vaWRlbnRpdHkvY2xhaW1zL29iamVjdGlkZW50aWZpZXI%2BPEF0dHJpYnV0ZVZhbHVlPjk4N2YyMThlLWQxMTMtNGFlZi04YmNkLWUwYTFkOGIwMzg4ODwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPWh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vaWRlbnRpdHkvY2xhaW1zL2Rpc3BsYXluYW1lPjxBdHRyaWJ1dGVWYWx1ZT5Vc2VyMTwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPWh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvZ3JvdXBzPjxBdHRyaWJ1dGVWYWx1ZT5iOTgxMWQxMy02Mjc1LTQ0MWYtODU5My0wNTQ2MWIwM2I4MDE8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT1odHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9pZGVudGl0eXByb3ZpZGVyPjxBdHRyaWJ1dGVWYWx1ZT5odHRwczovL3N0cy53aW5kb3dzLm5ldC8yMWVhOTE2Yi1kOTJmLTQ3ZjAtYmQ2NS1jNjdiOTcyZTY1YWUvPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9aHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9jbGFpbXMvYXV0aG5tZXRob2RzcmVmZXJlbmNlcz48QXR0cmlidXRlVmFsdWU%2BaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2F1dGhlbnRpY2F0aW9ubWV0aG9kL3Bhc3N3b3JkPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9aHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lPjxBdHRyaWJ1dGVWYWx1ZT5Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9aHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc3VybmFtZT48QXR0cmlidXRlVmFsdWU%2BMTwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPWh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWU%2BPEF0dHJpYnV0ZVZhbHVlPm5vYm9keUBub3doZXJlLmNvbTwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPC9BdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0yMDI0LTA5LTE4VDExOjE0OjQwLjA0OVogU2Vzc2lvbkluZGV4PV9lNjhmYzI0NC1kNTE3LTRlY2ItOTk4Zi03OGRjMGY0MjdhMDA%2BPEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY%2BdXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ%2BPC9Bc3NlcnRpb24%2BPC9zYW1scDpSZXNwb25zZT4%3D""";

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
    public TestResult isSAMLResponse() {
        try {
            var request = HttpRequest.httpRequest(rawRequest);
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var success = analysis.isSAMLMessage() && !analysis.isSAMLRequest();
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
            var body = request.parameterValue("SAMLResponse", HttpParameterType.BODY);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(body, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            return new TestResult(true, decodedSamlMessage.message(), null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

    @TestOrder.Order(4)
    public TestResult canApplyXsltAttack() throws Exception {
        try {
            var certificateTab = new CertificateTab();
            var certificateTabController = new CertificateTabController(certificateTab);
            var samlTabController = new SamlTabController(true, certificateTabController);
            var request = HttpRequest.httpRequest(rawRequest);
            var requestResponse = HttpRequestResponse.httpRequestResponse(request, null);
            samlTabController.setRequestResponse(requestResponse);
            samlTabController.applyXSLT("https://example.com");
            var infoMessageText = samlTabController.getInfoMessageText();

            var success = SamlTabController.XSLT_CONTENT_APPLIED.equals(infoMessageText);

            if (!success) {
                return new TestResult(false, infoMessageText, null);
            }

            request = samlTabController.getRequest();
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var body = request.parameterValue("SAMLResponse", HttpParameterType.BODY);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(body, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            return new TestResult(true, decodedSamlMessage.message(), null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }
}
