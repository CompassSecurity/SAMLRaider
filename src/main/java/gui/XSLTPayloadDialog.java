package gui;

import burp.BurpExtender;
import burp.api.montoya.core.BurpSuiteEdition;
import helpers.XSLTPayloads;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/// Dialog that asks for an XSLT attack flavor and the flavor-specific parameter.
/// For URL-based flavors (SAXON_UNPARSED_TEXT, XALAN_CLASS_INSTANTIATION) the user
/// can opt into Burp Collaborator (Pro only). For XALAN_RUNTIME_EXEC the parameter
/// is a shell command — no Collaborator shortcut makes sense.
public class XSLTPayloadDialog {

    private XSLTPayloadDialog() {}

    public record Selection(XSLTPayloads.Flavor flavor, String param) {}

    public static Optional<Selection> prompt(Component parent) {
        boolean isPro = BurpExtender.api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;

        var flavorCombo = new JComboBox<>(XSLTPayloads.Flavor.values());
        var paramLabel = new JLabel("URL:");
        var paramField = new JTextField("curl http://attacker/", 35);
        paramField.setText(""); // default empty for URL flavors
        var useCollab = new JCheckBox("Use Burp Collaborator", false);
        useCollab.setEnabled(isPro);
        if (!isPro) {
            useCollab.setToolTipText("Burp Collaborator is only available in Burp Suite Professional");
        }

        // Toggle label + Collaborator availability when flavor changes.
        Runnable refresh = () -> {
            XSLTPayloads.Flavor f = (XSLTPayloads.Flavor) flavorCombo.getSelectedItem();
            boolean isRuntime = f == XSLTPayloads.Flavor.XALAN_RUNTIME_EXEC;
            paramLabel.setText(isRuntime ? "Shell command:" : "URL:");
            useCollab.setEnabled(isPro && !isRuntime);
            if (isRuntime) useCollab.setSelected(false);
            paramField.setEnabled(!useCollab.isSelected());
            if (f == XSLTPayloads.Flavor.ALL) {
                paramLabel.setText("URL (used for SSRF probes; curl <url> auto-generated for RCE):");
            }
        };
        flavorCombo.addActionListener(e -> refresh.run());
        useCollab.addActionListener(e -> paramField.setEnabled(!useCollab.isSelected()));
        refresh.run();

        var flavorRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        flavorRow.add(new JLabel("Flavor:"));
        flavorRow.add(flavorCombo);

        var paramRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        paramRow.add(paramLabel);
        paramRow.add(paramField);

        var collabRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        collabRow.add(useCollab);

        var panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        panel.add(flavorRow, BorderLayout.NORTH);
        panel.add(paramRow, BorderLayout.CENTER);
        panel.add(collabRow, BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(
                parent, panel, "XSLT Attack", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) {
            return Optional.empty();
        }

        XSLTPayloads.Flavor flavor = (XSLTPayloads.Flavor) flavorCombo.getSelectedItem();
        String param;
        if (useCollab.isSelected()) {
            try {
                String payload = BurpExtender.api.collaborator()
                        .defaultPayloadGenerator()
                        .generatePayload()
                        .toString();
                param = "https://" + payload;
            } catch (Exception ex) {
                BurpExtender.api.logging().logToError(ex);
                JOptionPane.showMessageDialog(parent,
                        "Failed to generate Burp Collaborator payload.\n" + ex.getMessage(),
                        "Collaborator Error", JOptionPane.ERROR_MESSAGE);
                return Optional.empty();
            }
        } else {
            param = paramField.getText().trim();
            if (param.isEmpty()) {
                JOptionPane.showMessageDialog(parent,
                        "Please enter a " + paramLabel.getText().toLowerCase().replace(":", "") + ".",
                        "XSLT Attack", JOptionPane.WARNING_MESSAGE);
                return Optional.empty();
            }
        }
        return Optional.of(new Selection(flavor, param));
    }
}
