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
            
            SAMLResponse=PHNhbWxwOlJlc3BvbnNlIElEPSJfZmI1YWYwZjAtZjJiNi00OGI3LWEzZmUtNmUzMGEwYzhjN2QxIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyNC0wOS0xOFQxMToxNDo0My4wNTBaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9kZXN0aW5hdGlvbi8iIEluUmVzcG9uc2VUbz0iT05FTE9HSU5fY2RiZjg1Mzg3NmE4MzcyZDQwYjkzNDFhNGY5NzE0NDJmMDhiNDEzZCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI%2BPElzc3VlciB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI%2BaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMjFlYTkxNmItZDkyZi00N2YwLWJkNjUtYzY3Yjk3MmU2NWFlLzwvSXNzdWVyPjxzYW1scDpTdGF0dXM%2BPHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxBc3NlcnRpb24gSUQ9Il9lNjhmYzI0NC1kNTE3LTRlY2ItOTk4Zi03OGRjMGY0MjdhMDAiIElzc3VlSW5zdGFudD0iMjAyNC0wOS0xOFQxMToxNDo0My4wNDZaIiBWZXJzaW9uPSIyLjAiIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48SXNzdWVyPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIxZWE5MTZiLWQ5MmYtNDdmMC1iZDY1LWM2N2I5NzJlNjVhZS88L0lzc3Vlcj48U2lnbmF0dXJlIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48U2lnbmVkSW5mbz48Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8%2BPFJlZmVyZW5jZSBVUkk9IiNfZTY4ZmMyNDQtZDUxNy00ZWNiLTk5OGYtNzhkYzBmNDI3YTAwIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BPC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU%2BVjhQWDdnWEdIIFdiRkZiSHNid1QvMnRyOVlXSFVxbUFTZE9EIHRjaUtWdz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU%2BcjFEVzB1SURGQm5seXNLS0hJQTlUWVlGMXFEN3VUN1Nrb3ZDUmtFZ2Vub1lYbU1UZC9YS2lhSVY0WDFMSWxJMHNWMHFqNkZOVXR1MVlHb3lRM0pYRDZBNjFxd3ZJQUl5S3R2ZVFUY1o5SDcxOURVNkRweCBmdDJ0Y1A2bTJEMkJwaDlCVzJWSVExcU9jcGlBOU1TelJKZXR4NlBoTGk2eFp4NWdxbElGenlDR2dUakVHdzBBbmxxNm8yckhJVkVwZGVUaEl1ZTRGd2ZhTnU0YnJuNGcxSWh4UlFEL2NPVkdTNUJxQ0dqQXBwTHNJaVFzUVZPYiAvRGZGUFR5TEFKUG14U3JYa1dkZGd6cFpMWHBRNllPMXFwZXkxVGlVZkZDd1lFWWNzcnZEdDEzSHRrR3ZybjgyMGlLSEhPRzhrYWRBMHdKa0FFcDd3TFhCYzhaajhhNmtRPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSUM4RENDQWRpZ0F3SUJBZ0lRVU5ZU2NWWnAgYUZDaDhUIHd3RjhSVEFOQmdrcWhraUc5dzBCQVFzRkFEQTBNVEl3TUFZRFZRUURFeWxOYVdOeWIzTnZablFnUVhwMWNtVWdSbVZrWlhKaGRHVmtJRk5UVHlCRFpYSjBhV1pwWTJGMFpUQWVGdzB5TkRBNU1ETXhOREF6TURGYUZ3MHlOekE1TURNeE5EQXpNREJhTURReE1qQXdCZ05WQkFNVEtVMXBZM0p2YzI5bWRDQkJlblZ5WlNCR1pXUmxjbUYwWldRZ1UxTlBJRU5sY25ScFptbGpZWFJsTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE0NkxvbmFGdlp4UUJHUG8zSk5uLzdTQVJEcGFEIFZyd1pwSzNHM3p5WFB4NnZpd00wNHRQMzg1QlJlMmlseW82bHYgUTI1L0xuVFc5aE10WXVoY0R6c0RvMEdiSkxYbmN4S1ZoYWtvajBHUlR6YUw2WGl0IE5nZENGRTM4ZlpUb2Q4aThyUVYwem5nZnUgc2hqcXJVdXExUDZ4SXNxQSBPbERuZnRQOXdDNFhpellMNXJySm56eHlhQ3cwMTFpL3J4MjROcUQ4a0ZmVFZxdDFNdG1BTVdHVlpUYnNLeTV3WFdZZiBkenZNVVlsNlZIdkZxZTBoNmdoQy9TeFVudFRjeVFUZVFsWEg3YlhkSzZmVHM1dXdXZmdUYlJaYms0M3pPS3JmZzZRQVlRUFBpYW5YMDhwVnlGNmtGWFRwaFV6eks1YXZWNFVFQ3RTTHBvNlJCR1dMaFFJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUI5N1JyWTVkeTR0elA2WFRTWDU2bVZCR1kvTjczby9aSW9GMUxTV0lsZkJWcU1kWTI5RUpiWEVJaGF0VjdKZy9HMU9DVEtEb3hab01PM2UxWTZMeUxnMTgwOFpJamdCIHBkL24yU3hCZmlpSGZ0Y1FaMiBac0lRWnJaMmNjTnFiT1FqS3BDTzVZd1pWaFZSR01BMDlSTGEyai9SVjFnUDdZWE5HZ3ZhalFhcjkyaTJ4OWNXYSAvNXZJOFZRRnhyWlNRRkUzQmdQMiB5MDBKNDZFL0doa0tobWkwTE8gSDhPZDR4UWF2bE55ejYydUoyYmZhVnl3NHlTZXpadHVFMzdSdCBvSEk0MHNXTW9VODhCRnRyQTFNVzM5WVBqIFRIZk40SjcxdVdZIGo5Z0pYNlY4c08wUXp1amVXbGd1aDZ0VmtveWpQRnhtcVcgYUhxaVVFM2JjbTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE%2BPC9LZXlJbmZvPjwvU2lnbmF0dXJlPjxTdWJqZWN0PjxOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPm5vYm9keUBub3doZXJlLmNvbTwvTmFtZUlEPjxTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI%2BPFN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iT05FTE9HSU5fY2RiZjg1Mzg3NmE4MzcyZDQwYjkzNDFhNGY5NzE0NDJmMDhiNDEzZCIgTm90T25PckFmdGVyPSIyMDI0LTA5LTE4VDEyOjE0OjQyLjkzNFoiIFJlY2lwaWVudD0iaHR0cHM6Ly9kZXN0aW5hdGlvbi8iLz48L1N1YmplY3RDb25maXJtYXRpb24%2BPC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyNC0wOS0xOFQxMTowOTo0Mi45MzRaIiBOb3RPbk9yQWZ0ZXI9IjIwMjQtMDktMThUMTI6MTQ6NDIuOTM0WiI%2BPEF1ZGllbmNlUmVzdHJpY3Rpb24%2BPEF1ZGllbmNlPmh0dHBzOi8vZGVzdGluYXRpb24vPC9BdWRpZW5jZT48L0F1ZGllbmNlUmVzdHJpY3Rpb24%2BPC9Db25kaXRpb25zPjxBdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy90ZW5hbnRpZCI%2BPEF0dHJpYnV0ZVZhbHVlPjIxZWE5MTZiLWQ5MmYtNDdmMC1iZDY1LWM2N2I5NzJlNjVhZTwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9vYmplY3RpZGVudGlmaWVyIj48QXR0cmlidXRlVmFsdWU%2BOTg3ZjIxOGUtZDExMy00YWVmLThiY2QtZTBhMWQ4YjAzODg4PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vaWRlbnRpdHkvY2xhaW1zL2Rpc3BsYXluYW1lIj48QXR0cmlidXRlVmFsdWU%2BVXNlcjE8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9ncm91cHMiPjxBdHRyaWJ1dGVWYWx1ZT5iOTgxMWQxMy02Mjc1LTQ0MWYtODU5My0wNTQ2MWIwM2I4MDE8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9pZGVudGl0eS9jbGFpbXMvaWRlbnRpdHlwcm92aWRlciI%2BPEF0dHJpYnV0ZVZhbHVlPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIxZWE5MTZiLWQ5MmYtNDdmMC1iZDY1LWM2N2I5NzJlNjVhZS88L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9jbGFpbXMvYXV0aG5tZXRob2RzcmVmZXJlbmNlcyI%2BPEF0dHJpYnV0ZVZhbHVlPmh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9hdXRoZW50aWNhdGlvbm1ldGhvZC9wYXNzd29yZDwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9naXZlbm5hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5Vc2VyPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL3N1cm5hbWUiPjxBdHRyaWJ1dGVWYWx1ZT4xPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5ub2JvZHlAbm93aGVyZS5jb208L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjwvQXR0cmlidXRlU3RhdGVtZW50PjxBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjQtMDktMThUMTE6MTQ6NDAuMDQ5WiIgU2Vzc2lvbkluZGV4PSJfZTY4ZmMyNDQtZDUxNy00ZWNiLTk5OGYtNzhkYzBmNDI3YTAwIj48QXV0aG5Db250ZXh0PjxBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZDwvQXV0aG5Db250ZXh0Q2xhc3NSZWY%2BPC9BdXRobkNvbnRleHQ%2BPC9BdXRoblN0YXRlbWVudD48L0Fzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPgo%3D""";

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
            return new TestResult(SamlTabController.XSLT_CONTENT_APPLIED.equals(infoMessageText), infoMessageText, null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }
}
