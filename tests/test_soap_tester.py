import xml.etree.ElementTree as ET
import pytest
from unittest.mock import Mock
from SoapTester import SoapTester


def test_get_default_value():
    """Test the get_default_value method for various XSD types."""
    mock_type = Mock()

    # Test string type
    mock_type.name = 'string'
    assert SoapTester.get_default_value(None, mock_type, 'test') == '?'

    # Test boolean type
    mock_type.name = 'boolean'
    assert SoapTester.get_default_value(None, mock_type, 'test') is False

    # Test integer type
    mock_type.name = 'int'
    assert SoapTester.get_default_value(None, mock_type, 'test') == 0

    # Test decimal type
    mock_type.name = 'decimal'
    assert SoapTester.get_default_value(None, mock_type, 'test') == 0.0

    # Test unknown type
    mock_type.name = 'unknown'
    assert SoapTester.get_default_value(None, mock_type, 'test') is None


def test_format_xml():
    """Test the format_xml method for proper XML formatting."""
    raw_xml = '<root><child>value</child></root>'
    expected = '<root>\n  <child>value</child>\n</root>'
    formatted = SoapTester.format_xml(None, raw_xml)
    assert formatted.strip() == expected.strip()

    # Test invalid XML
    invalid_xml = '<root>unclosed'
    assert SoapTester.format_xml(None, invalid_xml) == invalid_xml


def test_strip_namespace_prefixes():
    """Test the strip_namespace_prefixes method for removing namespace prefixes."""
    xml_string = '<ns:root xmlns:ns="http://example.com"><ns:child ns:attr="value">text</ns:child></ns:root>'
    elem = ET.fromstring(xml_string)
    result = SoapTester.strip_namespace_prefixes(None, elem)

    assert result.tag == 'root'
    assert result[0].tag == 'child'
    assert result[0].attrib == {'attr': 'value'}
    assert result[0].text == 'text'
