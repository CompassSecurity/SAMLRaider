package gui;

import burp.BurpExtender;
import burp.api.montoya.ui.Theme;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.Serial;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Highlighter;
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

    // Search
    private final JTextField searchField;
    private final JLabel searchStatus;
    private final Highlighter.HighlightPainter searchPainter;
    private int currentMatchIndex = -1;
    private int[] matchPositions = new int[0]; // start positions of all matches

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

        // --- Search bar ---
        boolean dark = BurpExtender.api.userInterface().currentTheme() == Theme.DARK;
        searchPainter = new DefaultHighlighter.DefaultHighlightPainter(
                dark ? new Color(0x806030) : new Color(0xFFE08A));

        searchField = new JTextField();
        searchField.setFont(font.deriveFont(Font.PLAIN, 12f));
        searchField.setPreferredSize(new Dimension(220, 26));
        searchField.setToolTipText("Search XML (Enter = next, Shift+Enter = previous, Esc = close)");

        searchStatus = new JLabel("");
        searchStatus.setFont(font.deriveFont(Font.PLAIN, 11f));
        searchStatus.setForeground(dark ? new Color(0x999999) : new Color(0x666666));

        // Live search as you type
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { doSearch(); }
            @Override public void removeUpdate(DocumentEvent e)  { doSearch(); }
            @Override public void changedUpdate(DocumentEvent e) { doSearch(); }
        });

        // Enter = next match, Shift+Enter = prev, Escape = hide
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    if (e.isShiftDown()) jumpToMatch(-1); else jumpToMatch(1);
                } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    clearSearch();
                    textPane.requestFocusInWindow();
                }
            }
        });

        var searchBar = new JPanel(new BorderLayout(6, 0));
        searchBar.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
        var searchLabel = new JLabel("Find:");
        searchLabel.setFont(font.deriveFont(Font.PLAIN, 12f));
        searchBar.add(searchLabel, BorderLayout.WEST);
        searchBar.add(searchField, BorderLayout.CENTER);
        searchBar.add(searchStatus, BorderLayout.EAST);
        add(searchBar, BorderLayout.SOUTH);
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

    /* ------------------------------------------------------------------ */
    /*  Search                                                            */
    /* ------------------------------------------------------------------ */

    private void doSearch() {
        textPane.getHighlighter().removeAllHighlights();
        String query = searchField.getText();
        if (query == null || query.isEmpty()) {
            searchStatus.setText("");
            matchPositions = new int[0];
            currentMatchIndex = -1;
            return;
        }

        String text;
        try { text = doc.getText(0, doc.getLength()); }
        catch (BadLocationException e) { return; }

        String lowerText = text.toLowerCase();
        String lowerQuery = query.toLowerCase();

        // Find all matches
        java.util.List<Integer> positions = new java.util.ArrayList<>();
        int idx = 0;
        while ((idx = lowerText.indexOf(lowerQuery, idx)) != -1) {
            positions.add(idx);
            try {
                textPane.getHighlighter().addHighlight(idx, idx + query.length(), searchPainter);
            } catch (BadLocationException ignored) {}
            idx += query.length();
        }

        matchPositions = positions.stream().mapToInt(Integer::intValue).toArray();

        if (matchPositions.length == 0) {
            searchStatus.setText("No matches");
            currentMatchIndex = -1;
        } else {
            currentMatchIndex = 0;
            scrollToMatch(0);
            updateSearchStatus();
        }
    }

    private void jumpToMatch(int direction) {
        if (matchPositions.length == 0) return;
        currentMatchIndex = (currentMatchIndex + direction + matchPositions.length) % matchPositions.length;
        scrollToMatch(currentMatchIndex);
        updateSearchStatus();
    }

    private void scrollToMatch(int index) {
        if (index < 0 || index >= matchPositions.length) return;
        int pos = matchPositions[index];
        textPane.setCaretPosition(pos);
        // Select the match so it's visually obvious
        textPane.setSelectionStart(pos);
        textPane.setSelectionEnd(pos + searchField.getText().length());
        try {
            textPane.scrollRectToVisible(textPane.modelToView2D(pos).getBounds());
        } catch (BadLocationException ignored) {}
    }

    private void updateSearchStatus() {
        if (matchPositions.length == 0) {
            searchStatus.setText("No matches");
        } else {
            searchStatus.setText((currentMatchIndex + 1) + " / " + matchPositions.length);
        }
    }

    private void clearSearch() {
        searchField.setText("");
        textPane.getHighlighter().removeAllHighlights();
        matchPositions = new int[0];
        currentMatchIndex = -1;
        searchStatus.setText("");
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
