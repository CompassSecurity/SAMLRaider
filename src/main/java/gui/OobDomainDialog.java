package gui;

import burp.BurpExtender;
import burp.api.montoya.core.BurpSuiteEdition;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * Dialog that lets the user choose between Burp Collaborator and a
 * custom OOB domain for XXE/XSLT payloads.
 */
public class OobDomainDialog {

    private OobDomainDialog() {}

    /**
     * Show the dialog and return the chosen OOB URL, or empty if cancelled.
     */
    public static Optional<String> prompt(Component parent, String title) {
        boolean isPro = BurpExtender.api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;

        var useCollab = new JCheckBox("Use Burp Collaborator", isPro);
        useCollab.setEnabled(isPro);
        if (!isPro) {
            useCollab.setToolTipText("Burp Collaborator is only available in Burp Suite Professional");
        }

        var domainField = new JTextField(30);
        domainField.setEnabled(!isPro);
        var domainLabel = new JLabel("OOB Domain:");
        domainLabel.setEnabled(!isPro);

        useCollab.addActionListener(e -> {
            boolean custom = !useCollab.isSelected();
            domainField.setEnabled(custom);
            domainLabel.setEnabled(custom);
            if (custom) {
                domainField.requestFocusInWindow();
            }
        });

        var collabRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        collabRow.add(useCollab);

        var domainRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        domainRow.add(domainLabel);
        domainRow.add(domainField);

        var panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        panel.add(collabRow, BorderLayout.NORTH);
        panel.add(domainRow, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(
                parent, panel, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result != JOptionPane.OK_OPTION) {
            return Optional.empty();
        }

        if (useCollab.isSelected()) {
            try {
                String payload = BurpExtender.api.collaborator()
                        .defaultPayloadGenerator()
                        .generatePayload()
                        .toString();
                return Optional.of("https://" + payload);
            } catch (Exception ex) {
                BurpExtender.api.logging().logToError("Could not generate Collaborator payload: " + ex.getMessage());
                BurpExtender.api.logging().logToError(ex);
                JOptionPane.showMessageDialog(parent,
                        "Failed to generate Burp Collaborator payload.\n"
                        + "Make sure Collaborator is enabled in Burp settings.\n\n"
                        + ex.getMessage(),
                        "Collaborator Error", JOptionPane.ERROR_MESSAGE);
                return Optional.empty();
            }
        } else {
            String domain = domainField.getText().trim();
            if (domain.isEmpty()) {
                JOptionPane.showMessageDialog(parent,
                        "Please enter an OOB domain.", title, JOptionPane.WARNING_MESSAGE);
                return Optional.empty();
            }
            // Ensure it has a scheme
            if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
                domain = "https://" + domain;
            }
            return Optional.of(domain);
        }
    }
}
