import re
from PyQt6.QtGui import QSyntaxHighlighter, QColor, QTextCharFormat, QFont, QPalette
from PyQt6.QtWidgets import QApplication  # To get the global application palette


class XmlHighlighter(QSyntaxHighlighter):

    def __init__(self, parent=None):
        super().__init__(parent)

        # Determine if dark mode is active
        # Ensure QApplication instance exists, especially if highlighter can be created before app exec.
        app_instance = QApplication.instance()
        if app_instance is None:  # Fallback if no app instance (e.g. testing outside app)
            is_dark_mode = False
        else:
            current_palette = app_instance.palette()
            is_dark_mode = current_palette.color(QPalette.ColorRole.Base).lightnessF() < 0.5

        # Define color sets
        if is_dark_mode:
            # Dark Mode Colors (e.g., VSCode Dark+ inspired)
            tag_color = QColor("#569CD6")        # Blue for tags
            attribute_color = QColor("#9CDCFE")  # Light Blue/Cyan for attribute names
            value_color = QColor("#CE9178")      # Orange/Peach for attribute values
            comment_color = QColor("#6A9955")    # Green for comments
            cdata_color = QColor("#808080")      # Gray for CDATA
        else:
            # Light Mode Colors
            tag_color = QColor(0, 0, 255)           # Blue
            attribute_color = QColor(128, 0, 128)   # Purple for attribute names
            value_color = QColor(163, 21, 21)       # Dark Red for attribute values
            comment_color = QColor(0, 128, 0)       # Green for comments
            cdata_color = QColor(100, 100, 100)     # Dark Gray for CDATA

        self.formats = {}

        # Tag Format
        tag_char_format = QTextCharFormat()
        tag_char_format.setForeground(tag_color)
        tag_char_format.setFontWeight(QFont.Weight.Bold)
        self.formats["tag"] = tag_char_format

        # Attribute Name Format
        attribute_char_format = QTextCharFormat()
        attribute_char_format.setForeground(attribute_color)
        self.formats["attribute"] = attribute_char_format

        # Attribute Value Format
        value_char_format = QTextCharFormat()
        value_char_format.setForeground(value_color)
        self.formats["value"] = value_char_format

        # Comment Format
        comment_char_format = QTextCharFormat()
        comment_char_format.setForeground(comment_color)
        comment_char_format.setFontItalic(True)
        self.formats["comment"] = comment_char_format

        # CDATA Format
        cdata_char_format = QTextCharFormat()
        cdata_char_format.setForeground(cdata_color)
        self.formats["cdata"] = cdata_char_format

        # Define highlighting rules (using existing regex from original file)
        self.rules = []
        # Original regex: r"<[/?!]?\s*([a-zA-Z0-9_:]+)" - for the tag name itself
        self.rules.append((re.compile(r"<[/?!]?\s*([a-zA-Z0-9_:]+)"), self.formats["tag"]))
        # Original regex: r"\s*([/?]?)>" - for the closing brackets
        self.rules.append((re.compile(r"\s*([/?]?)>"), self.formats["tag"]))
        # Original regex: r'\s+([a-zA-Z0-9_:-]+)\s*=' - for attribute names
        self.rules.append((re.compile(r'\s+([a-zA-Z0-9_:-]+)\s*='), self.formats["attribute"]))
        # Original regex: r'=\s*("[^"]*"|\'[^\']*\')' - for attribute values
        self.rules.append((re.compile(r'=\s*("[^"]*"|\'[^\']*\')'), self.formats["value"]))

        # Comment rule (special handling in highlightBlock)
        self.comment_rule_regex = re.compile(r"<!--.*?-->")

        # CDATA rule (special handling in highlightBlock)
        self.cdata_rule_regex = re.compile(r"<!\[CDATA\[.*?]]>")

    def highlightBlock(self, text):
        # 1. Apply Comment Highlighting
        for match in self.comment_rule_regex.finditer(text):
            self.setFormat(match.start(), match.end() - match.start(), self.formats["comment"])

        # 2. Apply CDATA Highlighting
        # To prevent CDATA content from being styled by other rules,
        # we can iterate and skip other rules if current position is within CDATA.
        # However, a simpler way for this version is to rely on application order if regex are distinct enough
        # or if CDATA content itself doesn't usually match other XML structural regex.
        # For now, applying CDATA format directly.
        cdata_matches = list(self.cdata_rule_regex.finditer(text))
        for match in cdata_matches:
            self.setFormat(match.start(), match.end() - match.start(), self.formats["cdata"])

        # 3. Apply other rules (tags, attributes, values)
        for pattern, char_format in self.rules:
            for match in pattern.finditer(text):
                # Check if the current match is inside a CDATA block
                is_inside_cdata = False
                for cdata_match in cdata_matches:
                    if match.start() >= cdata_match.start() and match.end() <= cdata_match.end():
                        is_inside_cdata = True
                        break
                if is_inside_cdata:
                    continue  # Skip formatting if inside CDATA

                # Check if the current match is inside a Comment block
                # This is a simplified check. A more robust way involves checking previousBlockState
                # for multi-line comments.
                # For single-line comments, if the comment was already formatted, we might not need this,
                # but good for safety to avoid re-applying different formats to comment content.
                # However, the current comment regex is greedy (.*?), so it should consume content
                # that might look like tags.

                # Determine which part of the match to format
                # Based on original logic:
                # - For tags <...> and attribute names: format group 1
                # - For attribute values ="...": format group 0 (the whole match including quotes)
                # - For closing brackets > />: format group 0 (the whole match)

                try:
                    if pattern.pattern == r"<[/?!]?\s*([a-zA-Z0-9_:]+)" or \
                       pattern.pattern == r'\s+([a-zA-Z0-9_:-]+)\s*=':
                        # These rules target the first captured group (tag name, attribute name)
                        start = match.start(1)
                        length = match.end(1) - start
                        self.setFormat(start, length, char_format)
                    elif pattern.pattern == r'=\s*("[^"]*"|\'[^\']*\')':
                        # This rule targets the whole match (attribute value including quotes)
                        start = match.start(0)
                        length = match.end(0) - start
                        self.setFormat(start, length, char_format)
                    elif pattern.pattern == r"\s*([/?]?)>":
                        # This rule targets the whole match (closing brackets)
                        # Or match.start(1) if only the bracket itself, but original was likely whole match
                        start = match.start(0)
                        length = match.end(0) - start
                        self.setFormat(start, length, char_format)
                    else:
                        # Default/fallback: format the whole match if not specified
                        start = match.start(0)
                        length = match.end(0) - start
                        self.setFormat(start, length, char_format)
                except IndexError:
                    # Fallback if a group is expected but not found (should not happen with correct regex)
                    self.setFormat(match.start(), match.end() - match.start(), char_format)
