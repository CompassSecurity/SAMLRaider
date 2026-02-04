package gui;

import application.SamlTabController;
import helpers.CVE_2022_41912;
import helpers.CVE_2025_23369;
import helpers.CVE_2025_25291;
import helpers.CVE_2025_25292;
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
import model.BurpCertificate;
import net.miginfocom.swing.MigLayout;

public class SamlPanelAction extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private SamlTabController controller;

    private final JButton btnMessageReset = new JButton("Reset Message");
    private final JButton btnFormatXml = new JButton("Format XML");

    private final JButton btnXSWHelp = new JButton("?");
    private final JComboBox<String> cmbboxXSW = new JComboBox<>();
    private final JButton btnXSWPreview = new JButton("Preview in Browser...");
    private final JButton btnMatchAndReplace = new JButton("Match and Replace");
    private final JButton btnXSWApply = new JButton("Apply XSW");

    private final JButton btnTestXXE = new JButton("Test XXE");
    private final JButton btnTestXSLT = new JButton("Test XSLT");

    private final JComboBox<String> cmbboxCVE = new JComboBox<>();
    private final JButton btnCVEApply = new JButton("Apply CVE");
    private final JButton btnCVEHelp = new JButton("?");

    private final JButton btnSignatureHelp = new JButton("?");
    private final JComboBox<BurpCertificate> cmbboxCertificate = new JComboBox<>();
    private final JButton btnSignatureRemove = new JButton("Remove Signatures");
    private final JButton btnResignAssertion = new JButton("(Re-)Sign Assertion");
    private final JButton btnSendCertificate = new JButton("Store Certificate");
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

        btnFormatXml.addActionListener(event -> controller.formatXml());

        // --- Wire listeners ---
        btnXSWHelp.addActionListener(event -> controller.showXSWHelp());
        btnXSWPreview.addActionListener(event -> controller.showXSWPreview());
        btnMatchAndReplace.addActionListener(event -> showMatchAndReplaceDialog());
        btnXSWApply.addActionListener(event -> controller.applyXSW());

        btnTestXXE.addActionListener(event ->
                Optional.ofNullable(JOptionPane.showInputDialog(btnXSWApply, "Enter Burp Collaborator URL (e.g. https://xyz.burpcollaborator.net)"))
                        .ifPresent(controller::applyXXE));
        btnTestXSLT.addActionListener(event ->
                Optional.ofNullable(JOptionPane.showInputDialog(btnXSWApply, "Enter Burp Collaborator URL (e.g. https://xyz.burpcollaborator.net)"))
                        .ifPresent(controller::applyXSLT));

        cmbboxCVE.setModel(new DefaultComboBoxModel<>(new String[]{
                CVE_2022_41912.CVE, CVE_2025_23369.CVE,
                CVE_2025_25291.CVE, CVE_2025_25292.CVE }));
        btnCVEApply.addActionListener(event -> controller.applyCVE());
        btnCVEHelp.addActionListener(event -> controller.showCVEHelp());

        btnSignatureHelp.addActionListener(event -> controller.showSignatureHelp());
        btnSignatureRemove.addActionListener(event -> controller.removeSignature());
        btnResignAssertion.addActionListener(event -> controller.resignAssertion());
        btnSendCertificate.addActionListener(event -> controller.sendToCertificatesTab());
        btnResignMessage.addActionListener(event -> controller.resignMessage());

        // --- Compact layout: one row per category ---
        var panel = new JPanel(new MigLayout("insets 6 8 6 8, gap 4 6", "", ""));

        // Row 1: Message actions
        panel.add(new JLabel("Message"), "split");
        panel.add(btnMessageReset);
        panel.add(btnFormatXml, "wrap");

        // Row 2: XSW
        panel.add(new JLabel("XSW"), "split");
        panel.add(cmbboxXSW);
        panel.add(btnXSWApply);
        panel.add(btnMatchAndReplace);
        panel.add(btnXSWPreview);
        panel.add(btnXSWHelp, "wrap");

        // Row 3: CVE + XML attacks
        panel.add(new JLabel("CVE"), "split");
        panel.add(cmbboxCVE);
        panel.add(btnCVEApply);
        panel.add(btnCVEHelp);
        panel.add(new JLabel("  XML"), "gapleft 12");
        panel.add(btnTestXXE);
        panel.add(btnTestXSLT, "wrap");

        // Row 4: Signatures
        panel.add(new JLabel("Signing"), "split");
        panel.add(cmbboxCertificate);
        panel.add(btnResignAssertion);
        panel.add(btnResignMessage);
        panel.add(btnSignatureRemove);
        panel.add(btnSendCertificate);
        panel.add(btnSignatureHelp, "wrap");

        setLayout(new BorderLayout());
        add(panel, BorderLayout.NORTH);
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
        btnFormatXml.setEnabled(false);
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
        btnFormatXml.setEnabled(true);
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
