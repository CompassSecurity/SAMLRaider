package gui;

import java.awt.BorderLayout;
import java.awt.Color;
import javax.swing.JPanel;
import javax.swing.JTextPane;
import javax.swing.UIManager;
import javax.swing.border.MatteBorder;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;

public class SamlPanelStatus extends JPanel {

    private final JTextPane textPane;

    public SamlPanelStatus() {
        var styleContext = StyleContext.getDefaultStyleContext();
        var attributeSet = styleContext.addAttribute(SimpleAttributeSet.EMPTY, StyleConstants.Foreground, new Color(255, 140, 0));
        this.textPane = new JTextPane();
        this.textPane.setEditable(false);
        this.textPane.setCharacterAttributes(attributeSet, false);
        this.setLayout(new BorderLayout());
    }

    public void setText(String text) {
        this.textPane.setText(text);
        if ("".equals(text)) {
            this.remove(this.textPane);
            this.setBorder(null);
        } else {
            this.add(this.textPane);
            var borderColor = UIManager.getColor("Component.borderColor");
            this.setBorder(new MatteBorder(1, 0, 0, 0, borderColor));
        }
    }

    public String getText() {
        return this.textPane.getText();
    }
}
