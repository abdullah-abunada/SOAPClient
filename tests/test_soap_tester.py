import xml.etree.ElementTree as ET
import pytest
from unittest.mock import Mock, patch
from SoapTester import SoapTester


def test_get_default_value():
    """Test the get_default_value method for various XSD types."""
    mock_type = Mock()

    # Test string type
    mock_type.name = 'string'
    assert SoapTester.get_default_value(mock_type, 'test') == '?'

    # Test boolean type
    mock_type.name = 'boolean'
    assert SoapTester.get_default_value(mock_type, 'test') is False

    # Test integer type
    mock_type.name = 'int'
    assert SoapTester.get_default_value(mock_type, 'test') == 0

    # Test decimal type
    mock_type.name = 'decimal'
    assert SoapTester.get_default_value(mock_type, 'test') == 0.0

    # Test unknown type
    mock_type.name = 'unknown'
    assert SoapTester.get_default_value(mock_type, 'test') is None


def test_format_xml():
    """Test the format_xml method for proper XML formatting and empty tag handling."""
    raw_xml = '<root><child>value</child></root>'
    expected = '<root>\n  <child>value</child>\n</root>'
    formatted = SoapTester.format_xml(raw_xml)
    assert formatted == expected

    # Test empty child tag removal with BillsRec preservation, no extra whitespace
    raw_xml = '<MsgBody><RecCount>0</RecCount><BillsRec><BillRec></BillRec></BillsRec></MsgBody>'
    expected = '<MsgBody>\n  <RecCount>0</RecCount>\n  <BillsRec></BillsRec>\n</MsgBody>'
    formatted = SoapTester.format_xml(raw_xml)
    assert formatted == expected

    # Test namespace handling
    raw_xml = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:Test xmlns:ns="http://example.com"><ns:Child>value</ns:Child></ns:Test></soapenv:Body></soapenv:Envelope>'
    expected = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://example.com">\n  <soapenv:Body>\n    <ns:Test>\n      <ns:Child>value</ns:Child>\n    </ns:Test>\n  </soapenv:Body>\n</soapenv:Envelope>'
    formatted = SoapTester.format_xml(raw_xml)
    assert formatted == expected

    # Test invalid XML
    invalid_xml = '<root>unclosed'
    assert SoapTester.format_xml(invalid_xml) == invalid_xml


def test_strip_namespace_prefixes():
    """Test the strip_namespace_prefixes method for removing namespace prefixes."""
    xml_string = '<ns:root xmlns:ns="http://example.com"><ns:child ns:attr="value">text</ns:child></ns:root>'
    elem = ET.fromstring(xml_string)
    result = SoapTester.strip_namespace_prefixes(elem)

    assert result.tag == 'root'
    assert result[0].tag == 'child'
    assert result[0].attrib == {'attr': 'value'}
    assert result[0].text == 'text'


def test_dict_to_xml():
    """Test the dict_to_xml method for including BillsRec."""
    # Test with BillsRec present but empty
    data = {'MsgBody': {'RecCount': '0', 'BillsRec': {'BillRec': {}}}}
    expected = '<Response><MsgBody><RecCount>0</RecCount><BillsRec></BillsRec></MsgBody></Response>'
    result = SoapTester.dict_to_xml(data, 'Response')
    assert result == expected

    # Test with BillsRec absent
    data = {'MsgBody': {'RecCount': '0'}}
    expected = '<Response><MsgBody><RecCount>0</RecCount><BillsRec></BillsRec></MsgBody></Response>'
    result = SoapTester.dict_to_xml(data, 'Response')
    assert result == expected


def test_sign_xml_element_whitespace_removal():
    """Test that sign_xml_element removes whitespace from canonicalized content."""
    tester = SoapTester()
    tester.signing_certificate = Mock()
    tester.signing_private_key = Mock()
    tester.signing_private_key.sign.return_value = b'signature'

    xml_content = '<root><sign>value</sign><append></append></root>'
    tester.request_edit = Mock()
    tester.request_edit.toPlainText.return_value = xml_content
    tester.element_sign_combo = Mock()
    tester.element_sign_combo.currentText.return_value = 'sign'
    tester.element_append_combo = Mock()
    tester.element_append_combo.currentText.return_value = 'append'

    with patch.object(tester, 'canonicalize_element') as mock_canonicalize:
        # Simulate canonicalized content with whitespace
        mock_canonicalize.return_value = '<sign>value</sign>\n  '.encode('utf-16le')
        tester.sign_xml_element()

        # Check the content passed to sign
        sign_call_args = tester.signing_private_key.sign.call_args[0][0]
        expected_content = '<sign>value</sign>'.encode('utf-16le')
        assert sign_call_args == expected_content
