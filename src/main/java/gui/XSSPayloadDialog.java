package gui;

import helpers.ResponseXSS;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * Dialog that lets the user choose an XSS injection target and payload for
 * {@link ResponseXSS}.
 */
public class XSSPayloadDialog {

    private XSSPayloadDialog() {}

    public record Selection(ResponseXSS.Target target, String payload) {}

    public static Optional<Selection> prompt(Component parent) {
        var targetCombo = new JComboBox<>(ResponseXSS.Target.values());
        var payloadField = new JTextField(ResponseXSS.DEFAULT_PAYLOAD, 30);

        var targetRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        targetRow.add(new JLabel("Target:"));
        targetRow.add(targetCombo);

        var payloadRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        payloadRow.add(new JLabel("Payload:"));
        payloadRow.add(payloadField);

        var panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        panel.add(targetRow, BorderLayout.NORTH);
        panel.add(payloadRow, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(
                parent, panel, "XSS Injection", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result != JOptionPane.OK_OPTION) {
            return Optional.empty();
        }

        var target = (ResponseXSS.Target) targetCombo.getSelectedItem();
        // Empty payload is allowed — clears the field, which is sometimes useful
        // for probing whether an error reflects the attribute at all.
        var payload = payloadField.getText();
        return Optional.of(new Selection(target, payload));
    }
}
