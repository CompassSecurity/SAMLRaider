package livetesting;

import application.CertificateTabController;
import application.SamlMessageAnalyzer;
import application.SamlMessageDecoder;
import application.SamlTabController;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import gui.CertificateTab;

public class ApplyXsltTest {

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
            
            SAMLResponse=PHNhbWxwOlJlc3BvbnNlIElEPSJfZmQ2MDFlMjEtNWY4MS00NjllLTg4YzctZGE3MmRjY2YxMzU3IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNS0wNC0wNlQwNjo0MjozOS4yMTNaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zYW1sY2VudC9TaGliYm9sZXRoLnNzby9TQU1MMi9QT1NUIiBDb25zZW50PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y29uc2VudDp1bnNwZWNpZmllZCIgSW5SZXNwb25zZVRvPSJfNTQ1ZTYwZmUzNjAyYTA2ZDI1ZjI0MWI2MjJjNWE3NzMiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly9TQU1MV0lOLnNhbWwubGFuL2FkZnMvc2VydmljZXMvdHJ1c3Q8L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiIC8%2BPC9zYW1scDpTdGF0dXM%2BPEFzc2VydGlvbiBJRD0iX2YyN2Q2NDAzLTMyZjMtNDVlYy04YjI0LThiMmZiNGNhOTliMCIgSXNzdWVJbnN0YW50PSIyMDE1LTA0LTA2VDA2OjQyOjM5LjIxMloiIFZlcnNpb249IjIuMCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxJc3N1ZXI%2BaHR0cDovL1NBTUxXSU4uc2FtbC5sYW4vYWRmcy9zZXJ2aWNlcy90cnVzdDwvSXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiAvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2IiAvPjxkczpSZWZlcmVuY2UgVVJJPSIjX2YyN2Q2NDAzLTMyZjMtNDVlYy04YjI0LThiMmZiNGNhOTliMCI%2BPGRzOlRyYW5zZm9ybXM%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIiAvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIC8%2BPC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiIC8%2BPGRzOkRpZ2VzdFZhbHVlPmZvS0swY3JRc1lDb3VZVTJwdDlkdnlEZEk5WjRzNVowV0FIcnBjbEFmQTg9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8%2BPGRzOlNpZ25hdHVyZVZhbHVlPjVhL0JFR0F5WkZBcmFwRHJoS3B5Y0I3d0FEeHBOMXJ3Qk95NUFEeU1zbEZEWjJYYnJrNklMQlZkd1FoNzhYZDVPUXRBWGdhcCtac3g4ZElWRjVUTjRPN3M4VERUM1VrR0VSUXU0ZVRpc2poSmFOam5jK0hOWHRrdWJLblEyanBvR2RvRGZwZ2YyVUpJVnE3Yjl6WFF4SWtpNFY0RGNNT0pjbGhiaUl3STJHWEZsem03MGZXWURBa3VBa2JhQU93WDcxNmpiNnhrbU1oQTRrRUR5c3pPeEZsVWJMZEtwOTJINzREMHdsaG5JcVAyazZPTnp1VE1MZmpNR041RlplbnFaeUpVZzZJWDc5bWZmRnBDRzZ0Rk05d1J6YWVoVGhHUkxJUTJRdFloNE1jQll3QXExSnJMMlFYdXJTcEgwNmxyQXprMEQ3OUhLREJQUjYyWndzNTVKdz09PC9kczpTaWduYXR1cmVWYWx1ZT48S2V5SW5mbyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU%2BTUlJQzNEQ0NBY1NnQXdJQkFnSVFOMHU3SmZhS0ZyeFBvR3VQMEVlVmpUQU5CZ2txaGtpRzl3MEJBUXNGQURBcU1TZ3dKZ1lEVlFRREV4OUJSRVpUSUZOcFoyNXBibWNnTFNCVFFVMU1WMGxPTG5OaGJXd3ViR0Z1TUI0WERURTFNREl5TlRFM01URTBOMW9YRFRFMk1ESXlOVEUzTVRFME4xb3dLakVvTUNZR0ExVUVBeE1mUVVSR1V5QlRhV2R1YVc1bklDMGdVMEZOVEZkSlRpNXpZVzFzTG14aGJqQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQVBMVFlrYkJJdlBhMitLck92eG9pMWFsT2NPbnh6RlJsWkVMWWh5aUNqMmowaEt1UWQrZkIrT2dQNGZOdWFIL2RFYlNpWjBmRDNNdFEwbnJjNjVOVFlyWHBQcUFhc01FR3BWVk9lbWk0a2FLd3hyWU9EM05iRm9GeFFqdmpNVjlVUXQyUmFCZTE2MHNGZTU4bzVjV3ZOVnhYQTJTZjgxZkllSGxTQkVNYXZGT1FGUWtRYkRVL1htR3RXMFhqUWh5eWlKNE1FeTdad2d1MkhteHBpd05hNndTZmxEWFpJVVlxM2dVWitlRnI4a1RnQnJwZ0x0RDJsQWFhRjhlOVgwbjZ4aXN3RG9PUnM3MGNOaXlIZ1RONHl3TCsxalQrdk5qSG9WK1Y5YnRUY2ZyMGwvSnl0RnJDTlh4M3o2azhwRG1RVkdJZmJZN0o0blJkcXB6RWQ1TU9URUNBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQXFPQ0pNcUU3cFJCczVxdnRtSjU1cjdmL0hGNkIrU1JpanpYNGswQmc3R0dLUXNObjJYM0JDNU1ZQ2NWWWxtelh3OGs1Snh4eE1ja0V4R2xuU3ZwaCsyRHlaSk95c3NwTWoyTkt1c2VEU0dhQkdiaEpYSC92RjBGbTlQcy9UZjRCS0lCclBFMTRnaENwNHZ0YVhscGQxMy93MWVYU3dxUTJySVJFYm1pZEdobzZQOWhrVkg2RzhyaTJpQ2xTNzhFZGFraG9za2NjMzVVdlh0NG82Ujc3UlRBOS9qUTlOeWx4WW9qMGVZQWxrSWxHK3JTRFFweDhSWFJpTFF4c09sNUVwWHFtb0Q5ekdBRVdXQXhjbXpUQWpKRkZ6aXMxRjduNm5WdXY4U1ZhS2pRQkV6L25tc3RkdXhMT28yMERSL00wVkFRUXp3TURNOXVpaFhOUXdOV0VNdz09PC9kczpYNTA5Q2VydGlmaWNhdGU%2BPC9kczpYNTA5RGF0YT48L0tleUluZm8%2BPC9kczpTaWduYXR1cmU%2BPFN1YmplY3Q%2BPFN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJfNTQ1ZTYwZmUzNjAyYTA2ZDI1ZjI0MWI2MjJjNWE3NzMiIE5vdE9uT3JBZnRlcj0iMjAxNS0wNC0wNlQwNjo0NzozOS4yMTNaIiBSZWNpcGllbnQ9Imh0dHBzOi8vc2FtbGNlbnQvU2hpYmJvbGV0aC5zc28vU0FNTDIvUE9TVCIgLz48L1N1YmplY3RDb25maXJtYXRpb24%2BPC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNS0wNC0wNlQwNjo0MjozOS4yMTBaIiBOb3RPbk9yQWZ0ZXI9IjIwMTUtMDQtMDZUMDc6NDI6MzkuMjEwWiI%2BPEF1ZGllbmNlUmVzdHJpY3Rpb24%2BPEF1ZGllbmNlPmh0dHBzOi8vc2FtbGNlbnQvc2hpYmJvbGV0aDwvQXVkaWVuY2U%2BPC9BdWRpZW5jZVJlc3RyaWN0aW9uPjwvQ29uZGl0aW9ucz48QXR0cmlidXRlU3RhdGVtZW50PjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvdXBuIj48QXR0cmlidXRlVmFsdWU%2BYm93c2VyQHNhbWwubGFuPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL2NsYWltcy9Hcm91cCI%2BPEF0dHJpYnV0ZVZhbHVlPkRvbcOkbmVuLUJlbnV0emVyPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9InVybjpvaWQ6MS4zLjYuMS40LjEuNTkyMy4xLjEuMS42IiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI%2BPEF0dHJpYnV0ZVZhbHVlPmJvd3NlckBzYW1sLmxhbjwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPC9BdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNS0wNC0wNlQwNjo0MjozOS4xNzhaIj48QXV0aG5Db250ZXh0PjxBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvQXV0aG5Db250ZXh0Q2xhc3NSZWY%2BPC9BdXRobkNvbnRleHQ%2BPC9BdXRoblN0YXRlbWVudD48L0Fzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg%3D%3D&RelayState=ss%3Amem%3Af3a11b409a62a95ea2f4620efb845bb0ad02dfde2e68e372cebb823ae01a3694""";

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
