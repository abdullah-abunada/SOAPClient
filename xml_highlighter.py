import re
from PyQt6.QtGui import QSyntaxHighlighter, QColor, QTextCharFormat, QFont

class XmlHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.highlighting_rules = []

        # Tag format
        tag_format = QTextCharFormat()
        tag_format.setForeground(QColor("blue"))
        tag_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((re.compile(r"<[/?!]?\s*([a-zA-Z0-9_:]+)"), tag_format))
        self.highlighting_rules.append((re.compile(r"\s*([/?]?)>"), tag_format))

        # Attribute name format
        attribute_format = QTextCharFormat()
        attribute_format.setForeground(QColor("darkGreen"))
        self.highlighting_rules.append((re.compile(r'\s+([a-zA-Z0-9_:-]+)\s*=') , attribute_format))

        # Attribute value format
        value_format = QTextCharFormat()
        value_format.setForeground(QColor("red"))
        self.highlighting_rules.append((re.compile(r'=\s*("[^"]*"|\'[^\']*\')'), value_format))

        # Comment format
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("gray"))
        comment_format.setFontItalic(True)
        self.comment_rule = (re.compile(r"<!--.*?-->"), comment_format)

        # CDATA format
        cdata_format = QTextCharFormat()
        cdata_format.setForeground(QColor("purple"))
        self.cdata_rule = (re.compile(r"<!\[CDATA\[.*?]]>"), cdata_format)

    def highlightBlock(self, text):
        # Apply comment highlighting
        pattern, text_format = self.comment_rule
        for match in pattern.finditer(text):
            start, end = match.span()
            self.setFormat(start, end - start, text_format)

        # Apply CDATA highlighting
        pattern, text_format = self.cdata_rule
        for match in pattern.finditer(text):
            start, end = match.span()
            self.setFormat(start, end - start, text_format)

        # Apply other rules
        for pattern, text_format in self.highlighting_rules:
            if pattern.pattern == r"<[/?!]?\s*([a-zA-Z0-9_:]+)" or pattern.pattern == r'\s+([a-zA-Z0-9_:-]+)\s*=': # Tag names and Attributes
                for match in pattern.finditer(text):
                    start, end = match.span(1) # Capture group 1
                    self.setFormat(start, end - start, text_format)
            elif pattern.pattern == r'=\s*("[^"]*"|\'[^\']*\')': # Attribute values
                 for match in pattern.finditer(text):
                    # Highlight the entire match including quotes
                    self.setFormat(match.start(0), match.end(0) - match.start(0), text_format)
            else: # Closing brackets and other elements
                for match in pattern.finditer(text):
                    start, end = match.span()
                    self.setFormat(start, end - start, text_format)
