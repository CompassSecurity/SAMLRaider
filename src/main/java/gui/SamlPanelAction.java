package gui;

import application.SamlTabController;
import helpers.CVE_2025_23369;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.Serial;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

import helpers.CVE_2025_25291;
import helpers.CVE_2025_25292;
import model.BurpCertificate;
import net.miginfocom.swing.MigLayout;

public class SamlPanelAction extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private SamlTabController controller;

    private final JButton btnMessageReset = new JButton("Reset Message");

    private final JButton btnXSWHelp = new JButton("Help");
    private final JComboBox<String> cmbboxXSW = new JComboBox<>();
    private final JButton btnXSWPreview = new JButton("Preview in Browser...");
    private final JButton btnMatchAndReplace = new JButton("Match and Replace");
    private final JButton btnXSWApply = new JButton("Apply XSW");

    private final JButton btnTestXXE = new JButton("Test XXE");
    private final JButton btnTestXSLT = new JButton("Test XSLT");

    private final JComboBox<String> cmbboxCVE = new JComboBox<>();
    private final JButton btnCVEApply = new JButton("Apply CVE");
    private final JButton btnCVEHelp = new JButton("Help");

    private final JButton btnSignatureHelp = new JButton("Help");
    private final JComboBox<BurpCertificate> cmbboxCertificate = new JComboBox<>();
    private final JButton btnSignatureRemove = new JButton("Remove Signatures");
    private final JButton btnResignAssertion = new JButton("(Re-)Sign Assertion");
    private final JButton btnSendCertificate = new JButton("Send Certificate to SAML Raider Certificates");
    private final JButton btnResignMessage = new JButton("(Re-)Sign Message");


    public SamlPanelAction() {
        initialize();
    }

    public SamlPanelAction(SamlTabController controller) {
        this.controller = controller;
        initialize();
    }

    private void initialize() {
        btnMessageReset.addActionListener(event -> {
            controller.resetMessage();
        });

        var samlMessagePanel = new JPanel();
        samlMessagePanel.setBorder(BorderFactory.createTitledBorder("SAML Message"));
        samlMessagePanel.setLayout(new MigLayout());
        samlMessagePanel.add(btnMessageReset, "wrap");

        btnXSWHelp.addActionListener(event -> controller.showXSWHelp());

        btnXSWPreview.addActionListener(event -> controller.showXSWPreview());

        btnMatchAndReplace.addActionListener(event -> showMatchAndReplaceDialog());

        btnXSWApply.addActionListener(event -> controller.applyXSW());

        var xswAttacksPanel = new JPanel();
        xswAttacksPanel.setBorder(BorderFactory.createTitledBorder("XSW Attacks"));
        xswAttacksPanel.setLayout(new MigLayout());
        xswAttacksPanel.add(btnXSWHelp, "wrap");
        xswAttacksPanel.add(cmbboxXSW, "split 4");
        xswAttacksPanel.add(btnMatchAndReplace);
        xswAttacksPanel.add(btnXSWPreview);
        xswAttacksPanel.add(btnXSWApply, "wrap");

        btnTestXXE.addActionListener(event ->
                Optional.ofNullable(JOptionPane.showInputDialog(btnXSWApply, "Enter Burp Collaborator URL (e.g. https://xyz.burpcollaborator.net)"))
                        .ifPresent(controller::applyXXE));

        btnTestXSLT.addActionListener(event ->
                Optional.ofNullable(JOptionPane.showInputDialog(btnXSWApply, "Enter Burp Collaborator URL (e.g. https://xyz.burpcollaborator.net)"))
                        .ifPresent(controller::applyXSLT));

        var xmlAttacksPanel = new JPanel();
        xmlAttacksPanel.setBorder(BorderFactory.createTitledBorder("XML Attacks"));
        xmlAttacksPanel.setLayout(new MigLayout());
        xmlAttacksPanel.add(btnTestXXE, "split 2");
        xmlAttacksPanel.add(btnTestXSLT, "wrap");

        cmbboxCVE.setModel(new DefaultComboBoxModel<>(new String[]{
                CVE_2025_23369.CVE,
                CVE_2025_25291.CVE,
                CVE_2025_25292.CVE
        }));

        btnCVEApply.addActionListener(event -> controller.applyCVE());

        btnCVEHelp.addActionListener(event -> controller.showCVEHelp());

        var cvePanel = new JPanel();
        cvePanel.setBorder(BorderFactory.createTitledBorder("CVEs"));
        cvePanel.setLayout(new MigLayout());
        cvePanel.add(cmbboxCVE);
        cvePanel.add(btnCVEApply);
        cvePanel.add(btnCVEHelp, "wrap");

        btnSignatureHelp.addActionListener(event -> controller.showSignatureHelp());

        btnSignatureRemove.addActionListener(event -> controller.removeSignature());

        btnResignAssertion.addActionListener(event -> controller.resignAssertion());

        btnSendCertificate.addActionListener(event -> controller.sendToCertificatesTab());

        btnResignMessage.addActionListener(event -> controller.resignMessage());

        var signatureAttacksPanel = new JPanel();
        signatureAttacksPanel.setBorder(BorderFactory.createTitledBorder("Signature Attacks"));
        signatureAttacksPanel.setLayout(new MigLayout());
        signatureAttacksPanel.add(btnSignatureHelp, "wrap");
        signatureAttacksPanel.add(btnSignatureRemove, "split 2");
        signatureAttacksPanel.add(btnSendCertificate, "wrap");
        signatureAttacksPanel.add(cmbboxCertificate, "split 3");
        signatureAttacksPanel.add(btnResignAssertion);
        signatureAttacksPanel.add(btnResignMessage, "wrap");

        var actionPanels = new JPanel();
        var actionPanelConstraints = "wrap";
        actionPanels.setLayout(new MigLayout());
        actionPanels.add(samlMessagePanel, actionPanelConstraints);
        actionPanels.add(xswAttacksPanel, actionPanelConstraints);
        actionPanels.add(cvePanel, actionPanelConstraints);
        actionPanels.add(xmlAttacksPanel, actionPanelConstraints);
        actionPanels.add(signatureAttacksPanel, actionPanelConstraints);

        var scrollPane = new JScrollPane(actionPanels);
        scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));

        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER);
    }

    public void setCertificateList(List<BurpCertificate> list) {
        DefaultComboBoxModel<BurpCertificate> model = new DefaultComboBoxModel<BurpCertificate>();

        for (BurpCertificate cert : list) {
            model.addElement(cert);
        }
        cmbboxCertificate.setModel(model);
    }

    public BurpCertificate getSelectedCertificate() {
        return (BurpCertificate) cmbboxCertificate.getSelectedItem();
    }

    public void setXSWList(String[] xswTypes) {
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<String>(xswTypes);
        cmbboxXSW.setModel(model);
    }

    public String getSelectedXSW() {
        return (String) cmbboxXSW.getSelectedItem();
    }

    public String getSelectedCVE() {
        return (String) cmbboxCVE.getSelectedItem();
    }

    public void disableControls() {
        cmbboxCertificate.setEnabled(false);
        cmbboxXSW.setEnabled(false);
        btnXSWHelp.setEnabled(false);
        btnXSWPreview.setEnabled(false);
        btnMessageReset.setEnabled(false);
        btnXSWApply.setEnabled(false);
        btnSignatureHelp.setEnabled(false);
        btnSignatureRemove.setEnabled(false);
        btnResignAssertion.setEnabled(false);
        btnSendCertificate.setEnabled(false);
        btnResignMessage.setEnabled(false);
        btnMatchAndReplace.setEnabled(false);
        btnTestXXE.setEnabled(false);
        btnTestXSLT.setEnabled(false);
        cmbboxCVE.setEnabled(false);
        btnCVEApply.setEnabled(false);
        this.revalidate();
    }

    public void enableControls() {
        cmbboxCertificate.setEnabled(true);
        cmbboxXSW.setEnabled(true);
        btnXSWHelp.setEnabled(true);
        btnXSWPreview.setEnabled(true);
        btnMessageReset.setEnabled(true);
        btnXSWApply.setEnabled(true);
        btnSignatureHelp.setEnabled(true);
        btnSignatureRemove.setEnabled(true);
        btnResignAssertion.setEnabled(true);
        btnSendCertificate.setEnabled(true);
        btnResignMessage.setEnabled(true);
        btnMatchAndReplace.setEnabled(true);
        btnTestXXE.setEnabled(true);
        btnTestXSLT.setEnabled(true);
        cmbboxCVE.setEnabled(true);
        btnCVEApply.setEnabled(true);
        this.revalidate();
    }

    private void showMatchAndReplaceDialog() {
        HashMap<String, String> matchAndReplaceMap = controller.getMatchAndReplaceMap();

        JPanel dialogPanel = new JPanel();
        dialogPanel.setLayout(new BorderLayout());
        dialogPanel.add(new JLabel("Match and replace rules takes effect after apply XSW"), BorderLayout.NORTH);

        JPanel listPanel = new JPanel();
        JTextField matchInputText = new JTextField();
        JTextField replaceInputText = new JTextField();

        JButton addEntryButton = new JButton("\u2795");
        addEntryButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if (matchInputText.getText() != "" && replaceInputText.getText() != "") {
                    matchAndReplaceMap.put(matchInputText.getText(), replaceInputText.getText());
                    updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
                    SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
                }
            }
        });

        updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
        JOptionPane.showMessageDialog(this, listPanel, "Apply XSW - Match and Replace", JOptionPane.PLAIN_MESSAGE);
    }

    private void updateMatchAndReplaceList(JPanel listPanel, JTextField matchInputText, JTextField replaceInputText, JButton addEntryButton) {
        HashMap<String, String> matchAndReplaceMap = controller.getMatchAndReplaceMap();
        listPanel.setLayout(new GridBagLayout());
        listPanel.removeAll();
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0;
        c.gridy = 0;
        listPanel.add(new JLabel("Match:                                          "), c);
        c.gridx = 1;
        listPanel.add(new JLabel("Replace:                                        "), c);
        c.gridx = 0;
        c.gridy = 1;
        listPanel.add(matchInputText, c);
        c.gridx = 1;
        listPanel.add(replaceInputText, c);
        c.gridx = 2;
        listPanel.add(addEntryButton, c);

        c.gridy = 2;
        for (String matchRule : matchAndReplaceMap.keySet()) {
            c.gridx = 0;
            listPanel.add(new JLabel(matchRule), c);

            c.gridx = 1;
            listPanel.add(new JLabel(matchAndReplaceMap.get(matchRule)), c);
            JButton deleteEntryBtn = new JButton("\u2796");
            deleteEntryBtn.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent e) {
                    matchAndReplaceMap.remove(matchRule);
                    updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
                    SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
                }
            });
            c.gridx = 2;
            listPanel.add(deleteEntryBtn, c);
            c.gridy++;
        }
        listPanel.revalidate();
    }
}
