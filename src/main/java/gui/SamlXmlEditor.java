package gui;

import burp.BurpExtender;
import burp.api.montoya.ui.Theme;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.io.Serial;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

/**
 * Editable XML editor with syntax highlighting, built on JTextPane.
 * Uses a simple state-machine tokenizer — no external library needed,
 * so no Swing/ClassLoader conflicts inside Burp.
 */
public class SamlXmlEditor extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private enum Tk { TEXT, BRACKET, TAG_NAME, ATTR_NAME, ATTR_VALUE, COMMENT, CDATA, PI }

    private final JTextPane textPane;
    private final DefaultStyledDocument doc;
    private final Timer highlightTimer;
    private final AtomicBoolean modified = new AtomicBoolean(false);
    private volatile boolean suppressEvents = false;

    // Attribute sets for each token type
    private final SimpleAttributeSet aDefault   = new SimpleAttributeSet();
    private final SimpleAttributeSet aBracket   = new SimpleAttributeSet();
    private final SimpleAttributeSet aTagName   = new SimpleAttributeSet();
    private final SimpleAttributeSet aAttrName  = new SimpleAttributeSet();
    private final SimpleAttributeSet aAttrValue = new SimpleAttributeSet();
    private final SimpleAttributeSet aComment   = new SimpleAttributeSet();
    private final SimpleAttributeSet aCdata     = new SimpleAttributeSet();
    private final SimpleAttributeSet aPi        = new SimpleAttributeSet();

    public SamlXmlEditor() {
        super(new BorderLayout());

        doc = new DefaultStyledDocument();

        // Override to disable word-wrapping (XML reads better with horiz scroll)
        textPane = new JTextPane(doc) {
            @Serial
            private static final long serialVersionUID = 1L;
            @Override
            public boolean getScrollableTracksViewportWidth() {
                Component parent = getParent();
                if (parent == null) return true;
                return getUI().getPreferredSize(this).width <= parent.getWidth();
            }
        };

        textPane.setEditable(true);
        textPane.setEnabled(true);
        textPane.setFocusable(true);

        // Font: prefer Burp's editor font, fall back to monospaced
        Font burpFont = BurpExtender.api.userInterface().currentEditorFont();
        Font font = (burpFont != null) ? burpFont : new Font(Font.MONOSPACED, Font.PLAIN, 13);
        textPane.setFont(font);

        applyThemeColors(font);

        // Debounced highlighting: re-color 150 ms after last keystroke
        highlightTimer = new Timer(150, e -> applyHighlighting());
        highlightTimer.setRepeats(false);

        doc.addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { onEdit(); }
            @Override public void removeUpdate(DocumentEvent e)  { onEdit(); }
            @Override public void changedUpdate(DocumentEvent e) { /* style changes — ignore */ }
            private void onEdit() {
                if (!suppressEvents) {
                    modified.set(true);
                    highlightTimer.restart();
                }
            }
        });

        var scroll = new JScrollPane(textPane);
        scroll.setBorder(null);
        add(scroll, BorderLayout.CENTER);
    }

    /* ------------------------------------------------------------------ */
    /*  Theme                                                             */
    /* ------------------------------------------------------------------ */

    private void applyThemeColors(Font font) {
        boolean dark = BurpExtender.api.userInterface().currentTheme() == Theme.DARK;

        textPane.setBackground(dark ? new Color(0x1E1F22) : Color.WHITE);
        textPane.setForeground(dark ? new Color(0xD6D6D6) : new Color(0x1F2328));
        textPane.setCaretColor(dark ? new Color(0xEDEDED) : Color.BLACK);
        textPane.setSelectionColor(dark ? new Color(0x264F78) : new Color(0xBBDDFF));

        setAttr(aDefault,   font, dark ? 0xD6D6D6 : 0x1F2328, false);
        setAttr(aBracket,   font, dark ? 0x808080 : 0x333333, false);
        setAttr(aTagName,   font, dark ? 0x569CD6 : 0x0000FF, false);
        setAttr(aAttrName,  font, dark ? 0x9CDCFE : 0xA31515, false);
        setAttr(aAttrValue, font, dark ? 0xCE9178 : 0x0451A5, false);
        setAttr(aComment,   font, dark ? 0x6A9955 : 0x008000, true);
        setAttr(aCdata,     font, dark ? 0xD7BA7D : 0x800000, false);
        setAttr(aPi,        font, dark ? 0x808080 : 0x808080, true);
    }

    private static void setAttr(SimpleAttributeSet a, Font font, int rgb, boolean italic) {
        StyleConstants.setFontFamily(a, font.getFamily());
        StyleConstants.setFontSize(a, font.getSize());
        StyleConstants.setForeground(a, new Color(rgb));
        StyleConstants.setItalic(a, italic);
        StyleConstants.setBold(a, false);
    }

    /* ------------------------------------------------------------------ */
    /*  XML tokenizer (state machine)                                     */
    /* ------------------------------------------------------------------ */

    private Tk[] tokenize(String text) {
        Tk[] tokens = new Tk[text.length()];
        Arrays.fill(tokens, Tk.TEXT);
        int len = text.length();
        int i = 0;

        while (i < len) {
            if (text.charAt(i) != '<') { i++; continue; }

            if (regionMatches(text, i, "<!--")) {
                int end = text.indexOf("-->", i + 4);
                int endPos = (end == -1) ? len : end + 3;
                Arrays.fill(tokens, i, Math.min(endPos, len), Tk.COMMENT);
                i = endPos;
            } else if (regionMatches(text, i, "<![CDATA[")) {
                int end = text.indexOf("]]>", i + 9);
                int endPos = (end == -1) ? len : end + 3;
                Arrays.fill(tokens, i, Math.min(endPos, len), Tk.CDATA);
                i = endPos;
            } else if (i + 1 < len && text.charAt(i + 1) == '?') {
                int end = text.indexOf("?>", i + 2);
                int endPos = (end == -1) ? len : end + 2;
                Arrays.fill(tokens, i, Math.min(endPos, len), Tk.PI);
                i = endPos;
            } else {
                // Regular tag: <name ... > or </name ... >
                tokens[i++] = Tk.BRACKET;                          // <
                if (i < len && text.charAt(i) == '/') {
                    tokens[i++] = Tk.BRACKET;                      // /
                }
                while (i < len && isNameChar(text.charAt(i))) {
                    tokens[i++] = Tk.TAG_NAME;
                }
                i = tokenizeInsideTag(text, tokens, i);
            }
        }
        return tokens;
    }

    /** Tokenize attribute region inside a tag until closing '>' */
    private int tokenizeInsideTag(String text, Tk[] tokens, int i) {
        int len = text.length();
        while (i < len) {
            char c = text.charAt(i);
            if (c == '>') {
                tokens[i++] = Tk.BRACKET;
                return i;
            } else if (c == '/') {
                tokens[i++] = Tk.BRACKET;
            } else if (c == '=') {
                tokens[i++] = Tk.BRACKET;
            } else if (c == '"' || c == '\'') {
                char q = c;
                tokens[i++] = Tk.ATTR_VALUE;
                while (i < len && text.charAt(i) != q) { tokens[i++] = Tk.ATTR_VALUE; }
                if (i < len) { tokens[i++] = Tk.ATTR_VALUE; }     // closing quote
            } else if (isNameStartChar(c)) {
                while (i < len && isNameChar(text.charAt(i))) { tokens[i++] = Tk.ATTR_NAME; }
            } else {
                i++;  // whitespace
            }
        }
        return i;
    }

    /* ------------------------------------------------------------------ */
    /*  Apply highlighting                                                */
    /* ------------------------------------------------------------------ */

    private void applyHighlighting() {
        String text;
        try { text = doc.getText(0, doc.getLength()); }
        catch (BadLocationException e) { return; }
        if (text.isEmpty()) return;

        Tk[] tokens = tokenize(text);

        // Group consecutive same-type tokens into runs and apply style per run
        int runStart = 0;
        Tk runType = tokens[0];
        for (int i = 1; i <= tokens.length; i++) {
            Tk t = (i < tokens.length) ? tokens[i] : null;
            if (t != runType) {
                doc.setCharacterAttributes(runStart, i - runStart, attrFor(runType), true);
                runStart = i;
                runType = t;
            }
        }
    }

    private SimpleAttributeSet attrFor(Tk token) {
        return switch (token) {
            case BRACKET    -> aBracket;
            case TAG_NAME   -> aTagName;
            case ATTR_NAME  -> aAttrName;
            case ATTR_VALUE -> aAttrValue;
            case COMMENT    -> aComment;
            case CDATA      -> aCdata;
            case PI         -> aPi;
            default         -> aDefault;
        };
    }

    /* ------------------------------------------------------------------ */
    /*  Char classification helpers                                       */
    /* ------------------------------------------------------------------ */

    private static boolean regionMatches(String text, int pos, String prefix) {
        return text.regionMatches(pos, prefix, 0, prefix.length());
    }

    private static boolean isNameStartChar(char c) {
        return Character.isLetter(c) || c == '_' || c == ':';
    }

    private static boolean isNameChar(char c) {
        return Character.isLetterOrDigit(c) || c == ':' || c == '-' || c == '.' || c == '_';
    }

    /* ------------------------------------------------------------------ */
    /*  Public API                                                        */
    /* ------------------------------------------------------------------ */

    public void setText(String text) {
        suppressEvents = true;
        try {
            textPane.setText(text != null ? text : "");
            textPane.setCaretPosition(0);
            modified.set(false);
        } finally {
            suppressEvents = false;
        }
        applyHighlighting();
    }

    public String getText() {
        try { return doc.getText(0, doc.getLength()); }
        catch (BadLocationException e) { return textPane.getText(); }
    }

    public void setEditable(boolean editable) {
        textPane.setEditable(editable);
        textPane.setEnabled(true);
        textPane.setFocusable(true);
    }

    public boolean isModified() {
        return modified.get();
    }

    public void resetModified() {
        modified.set(false);
    }

    public String selectedText() {
        return textPane.getSelectedText();
    }
}
