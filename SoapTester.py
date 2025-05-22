import sys
import zeep
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QTextEdit, QLineEdit, QFileDialog, QComboBox, QLabel, QMessageBox, QInputDialog)
from PyQt6.QtCore import Qt
import xml.etree.ElementTree as ET
from xml.dom import minidom
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import requests
from zeep.transports import Transport
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime
import uuid
import re
from lxml import etree

class SoapTester(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOAP Service Tester")
        self.setGeometry(100, 100, 1200, 800)
        self.client = None
        self.signing_certificate = None
        self.signing_private_key = None
        self.verifying_certificate = None
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)

        wsdl_layout = QHBoxLayout()
        self.wsdl_url_input = QLineEdit()
        self.wsdl_url_input.setPlaceholderText("Enter WSDL URL or leave blank to import file")
        wsdl_button = QPushButton("Import WSDL")
        wsdl_button.clicked.connect(self.import_wsdl)
        wsdl_layout.addWidget(self.wsdl_url_input)
        wsdl_layout.addWidget(wsdl_button)
        layout.addLayout(wsdl_layout)

        self.service_url_input = QLineEdit()
        self.service_url_input.setPlaceholderText("Service URL")
        layout.addWidget(self.service_url_input)

        cert_layout = QHBoxLayout()
        sign_cert_button = QPushButton("Import Signing Certificate")
        sign_cert_button.clicked.connect(self.import_signing_certificate)
        verify_cert_button = QPushButton("Import Verifying Certificate")
        verify_cert_button.clicked.connect(self.import_verifying_certificate)
        self.sign_cert_label = QLabel("No signing certificate loaded")
        self.verify_cert_label = QLabel("No verifying certificate loaded")
        cert_layout.addWidget(sign_cert_button)
        cert_layout.addWidget(self.sign_cert_label)
        cert_layout.addWidget(verify_cert_button)
        cert_layout.addWidget(self.verify_cert_label)
        layout.addLayout(cert_layout)

        sign_layout = QHBoxLayout()
        self.element_sign_combo = QComboBox()
        self.element_sign_combo.addItem("Select element to sign")
        self.element_append_combo = QComboBox()
        self.element_append_combo.addItem("Select element to append signature")
        sign_button = QPushButton("Sign and Append")
        sign_button.clicked.connect(self.sign_xml_element)
        sign_layout.addWidget(QLabel("Sign Element:"))
        sign_layout.addWidget(self.element_sign_combo)
        sign_layout.addWidget(QLabel("Append Signature To:"))
        sign_layout.addWidget(self.element_append_combo)
        sign_layout.addWidget(sign_button)
        layout.addLayout(sign_layout)

        editor_layout = QHBoxLayout()
        self.request_edit = QTextEdit()
        self.request_edit.setPlaceholderText("XML Request will appear here")
        self.response_edit = QTextEdit()
        self.response_edit.setPlaceholderText("XML Response will appear here")
        self.response_edit.setReadOnly(True)
        editor_layout.addWidget(self.request_edit)
        editor_layout.addWidget(self.response_edit)
        layout.addLayout(editor_layout)

        send_button = QPushButton("Send Request")
        send_button.clicked.connect(self.send_request)
        layout.addWidget(send_button)

    def strip_namespace_prefixes(self, elem):
        """
        Remove namespace prefixes from element tags and attributes recursively.
        """
        # Remove prefix from tag
        if isinstance(elem.tag, str):
            elem.tag = etree.QName(elem).localname

        # Create new attributes without prefixes
        new_attrib = {}
        for attr_name, attr_value in elem.attrib.items():
            new_attr_name = etree.QName(attr_name).localname
            new_attrib[new_attr_name] = attr_value

        # Clear and reassign attributes
        elem.attrib.clear()
        elem.attrib.update(new_attrib)

        # Process children recursively
        for child in elem:
            self.strip_namespace_prefixes(child)

        return elem

    def canonicalize_element(self, element):
        parser = etree.XMLParser(remove_blank_text=True)
        root = etree.fromstring(ET.tostring(element, encoding='utf-8'), parser=parser)
        cleaned_root = self.strip_namespace_prefixes(root)
        # Canonicalize XML (c14n)
        canonicalized_bytes = etree.tostring(cleaned_root, method="c14n", exclusive=True, with_comments=False)
        # Decode to string and re-encode as UTF-16LE to match .NET Encoding.Unicode
        canonicalized_str = canonicalized_bytes.decode('utf-8')  # decode back to str
        print(canonicalized_str)
        utf16le_encoded = canonicalized_str.encode('utf-16le')   # encode as .NET expects

        return utf16le_encoded

    def import_wsdl(self):
        wsdl_url = self.wsdl_url_input.text().strip()
        if not wsdl_url:
            wsdl_file, _ = QFileDialog.getOpenFileName(self, "Select WSDL File", "", "WSDL Files (*.wsdl *.xml)")
            if wsdl_file:
                wsdl_url = f"file://{wsdl_file}"
        if wsdl_url:
            try:
                session = requests.Session()
                session.verify = False
                transport = Transport(session=session)
                self.client = zeep.Client(wsdl=wsdl_url, transport=transport)
                self.service_url_input.setText(str(self.client.service._binding_options['address']))
                self.generate_xml_request()
                self.populate_element_combos()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load WSDL: {str(e)}")

    def generate_xml_request(self):
        if not self.client:
            return
        try:
            # Get the first available service and port
            service = list(self.client.wsdl.services.values())[0]
            port = list(service.ports.values())[0]
            operation_name, operation = list(port.binding._operations.items())[0]

            input_message = operation.input
            if not input_message:
                raise ValueError("No input message found for the operation.")

            # Build base envelope
            envelope = ET.Element('{http://schemas.xmlsoap.org/soap/envelope/}Envelope')
            envelope.set('xmlns:soapenv', 'http://schemas.xmlsoap.org/soap/envelope/')
            header = ET.SubElement(envelope, '{http://schemas.xmlsoap.org/soap/envelope/}Header')
            body = ET.SubElement(envelope, '{http://schemas.xmlsoap.org/soap/envelope/}Body')

            # Build the operation wrapper
            nsmap = input_message.body.qname.namespace
            operation_elem = ET.SubElement(body, f'{{{nsmap}}}{operation_name}')
            element_def = input_message.body.type

            # Recursively build XML elements based on the input type
            def build_elements(parent_elem, schema_type, depth=0):
                if depth > 10:
                    return
                for name, element in schema_type.elements:
                    child_elem = ET.SubElement(parent_elem, f'{{{element.qname.namespace}}}{name}')
                    if isinstance(element.type, zeep.xsd.ComplexType):
                        build_elements(child_elem, element.type, depth + 1)
                    else:
                        child_elem.text = self.get_default_value(element.type, name)

            build_elements(operation_elem, element_def)

            # Format and display
            formatted = self.format_xml(ET.tostring(envelope, encoding='unicode', short_empty_elements=False))
            self.request_edit.setText(formatted)

            # Populate element comboboxes
            self.populate_element_combos()

        except Exception as e:
            fallback_xml = self.format_xml('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                                           '<soapenv:Header/><soapenv:Body><FallbackOperation/></soapenv:Body></soapenv:Envelope>')
            self.request_edit.setText(fallback_xml)
            QMessageBox.warning(self, "Warning", f"Failed to generate XML from WSDL: {str(e)}. Fallback request shown.")

    def create_default_instance(self, type_obj, factory, schema, depth=0, max_depth=10):
        if depth > max_depth:
            return None

        if not hasattr(type_obj, '_xsd_type'):
            return None

        xsd_type = type_obj._xsd_type
        if isinstance(xsd_type, zeep.xsd.ComplexType):
            kwargs = {}
            for element in xsd_type.elements:
                name = element[0]
                elem_type = element[1].type
                if isinstance(elem_type, zeep.xsd.ComplexType):
                    nested_type = factory(elem_type)
                    nested_instance = self.create_default_instance(nested_type, factory, schema, depth + 1, max_depth)
                    kwargs[name] = nested_instance
                else:
                    kwargs[name] = self.get_default_value(elem_type, name)
            return type_obj(**kwargs)
        else:
            return self.get_default_value(xsd_type, type_obj.__class__.__name__)

    def get_default_value(self, xsd_type, name):
        if xsd_type.name in ('string', 'anyURI', 'QName'):
            return '?'
        elif xsd_type.name == 'boolean':
            return False
        elif xsd_type.name in ('int', 'long', 'short', 'byte', 'unsignedInt', 'unsignedLong', 'unsignedShort', 'unsignedByte'):
            return 0
        elif xsd_type.name in ('decimal', 'float', 'double'):
            return 0.0
        elif xsd_type.name == 'dateTime':
            return datetime.now().isoformat()
        elif xsd_type.name == 'guid':
            return str(uuid.uuid4())
        elif xsd_type.name == 'base64Binary':
            return ''
        else:
            return None

    def format_xml(self, xml_string):
        try:
            parsed = minidom.parseString(xml_string)
            pretty_xml = parsed.toprettyxml(indent="  ")
            # Remove extra empty lines
            cleaned_xml = re.sub(r'\n\s*\n+', '\n', pretty_xml)
            # Remove leading/trailing whitespace and ensure single newlines
            cleaned_xml = '\n'.join(line.rstrip() for line in cleaned_xml.splitlines() if line.strip())
            cleaned_xml = re.sub(r'<([a-zA-Z0-9_:.-]+)([^>]*)\s*/>', r'<\1\2></\1>', cleaned_xml)
            return cleaned_xml
        except Exception:
            return xml_string

    def populate_element_combos(self):
        self.element_sign_combo.clear()
        self.element_append_combo.clear()
        self.element_sign_combo.addItem("Select element to sign")
        self.element_append_combo.addItem("Select element to append signature")

        if not self.client:
            return

        try:
            # Get the first available service, port, and operation
            service = list(self.client.wsdl.services.values())[0]
            port = list(service.ports.values())[0]
            operation_name, operation = list(port.binding._operations.items())[0]

            input_message = operation.input
            if not input_message or not input_message.body:
                return

            # Get the schema type for the input message
            element_def = input_message.body.type

            # Recursively collect element names
            def collect_element_names(schema_type, names=None, depth=0):
                if names is None:
                    names = set()
                if depth > 10:
                    return names
                for name, element in schema_type.elements:
                    names.add(name)
                    if isinstance(element.type, zeep.xsd.ComplexType):
                        collect_element_names(element.type, names, depth + 1)
                return names

            # Get sorted list of element names
            element_names = sorted(collect_element_names(element_def))

            # Populate comboboxes with element names
            self.element_sign_combo.addItems(element_names)
            self.element_append_combo.addItems(element_names)

        except Exception as e:
            print(f"[DEBUG] Failed to populate element combos from WSDL: {str(e)}")

    def import_signing_certificate(self):
        cert_file, _ = QFileDialog.getOpenFileName(self, "Select Signing Certificate File", "", "Certificate Files (*.pem *.crt *.cer *.p12 *.pfx)")
        if cert_file:
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                password, ok = QInputDialog.getText(self, "Certificate Password", "Enter password for certificate/private key:", QLineEdit.EchoMode.Password)
                if not ok:
                    raise ValueError("Certificate password required")

                try:
                    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(cert_data, password.encode() if password else None)
                    if certificate is None:
                        raise ValueError("No certificate found in PKCS#12 file")
                    if private_key is None:
                        raise ValueError("No private key found in PKCS#12 file")
                    self.signing_certificate = certificate
                    self.signing_private_key = private_key
                    self.sign_cert_label.setText(f"Signing Certificate: {cert_file.split('/')[-1]}")
                except ValueError as e:
                    error_msg = str(e).lower()
                    if "invalid password" in error_msg or "mac verify failure" in error_msg:
                        raise ValueError("Incorrect password for PKCS#12 file")
                    elif "could not deserialize" in error_msg:
                        raise ValueError("Invalid PKCS#12 file format or corrupted data. Ensure the file is a valid PKCS#12 container.")
                    else:
                        raise ValueError(f"PKCS#12 error: {str(e)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load signing certificate/key: {str(e)}")
                self.signing_certificate = None
                self.signing_private_key = None
                self.sign_cert_label.setText("No signing certificate loaded")

    def import_verifying_certificate(self):
        cert_file, _ = QFileDialog.getOpenFileName(self, "Select Verifying Certificate File", "", "Certificate Files (*.pem *.crt *.cer)")
        if cert_file:
            try:
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                try:
                    self.verifying_certificate = x509.load_pem_x509_certificate(cert_data)
                except ValueError:
                    self.verifying_certificate = x509.load_der_x509_certificate(cert_data)
                self.verify_cert_label.setText(f"Verifying Certificate: {cert_file.split('/')[-1]}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load verifying certificate: {str(e)}")
                self.verifying_certificate = None
                self.verify_cert_label.setText("No verifying certificate loaded")

    def sign_xml_element(self):
        if not self.signing_certificate or not self.signing_private_key:
            QMessageBox.warning(self, "Warning", "Please import a signing certificate and private key first.")
            return

        selected_sign_name = self.element_sign_combo.currentText()
        selected_append_name = self.element_append_combo.currentText()

        if selected_sign_name == "Select element to sign" or selected_append_name == "Select element to append signature":
            QMessageBox.warning(self, "Warning", "Please select elements to sign and append the signature.")
            return

        try:
            xml_content = self.request_edit.toPlainText()
            root = ET.fromstring(xml_content)

            # Find elements by local name regardless of namespace
            def find_by_localname(elem, localname):
                return [e for e in elem.iter() if isinstance(e.tag, str) and e.tag.split('}')[-1] == localname]

            sign_targets = find_by_localname(root, selected_sign_name)
            append_targets = find_by_localname(root, selected_append_name)

            if not sign_targets or not append_targets:
                QMessageBox.warning(self, "Warning", "Selected sign or append element not found in XML.")
                return

            sign_target = sign_targets[0]
            append_target = append_targets[0]

            # Sign the entire deep tree of the selected element (including all descendants)
            content = self.canonicalize_element(sign_target)
            print(content)
            signature = self.signing_private_key.sign(
                content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()

            # Append the signature to the selected append element
            append_target.text = signature_b64

            # Format the updated XML and display it
            formatted_xml = self.format_xml(ET.tostring(root, encoding='unicode', short_empty_elements=False))
            self.request_edit.setText(formatted_xml)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to sign XML: {str(e)}")

    def verify_response_signature(self, response_xml: str):
        if not self.verifying_certificate:
            return

        selected_sign_name = self.element_sign_combo.currentText()
        selected_append_name = self.element_append_combo.currentText()

        if selected_sign_name == "Select element to sign" or selected_append_name == "Select element to append signature":
            QMessageBox.warning(self, "Warning", "Please select valid elements for verification.")
            return

        try:
            root = ET.fromstring(response_xml)

            def find_by_localname(elem, localname):
                return [e for e in elem.iter() if isinstance(e.tag, str) and e.tag.split('}')[-1] == localname]

            sign_targets = find_by_localname(root, selected_sign_name)
            append_targets = find_by_localname(root, selected_append_name)

            if not sign_targets or not append_targets:
                QMessageBox.warning(self, "Warning", "Selected sign or append element not found in response XML.")
                return

            sign_target = sign_targets[0]
            append_target = append_targets[0]

            # Extract the signature from the append_target element
            signature_b64 = append_target.text
            if not signature_b64:
                QMessageBox.warning(self, "Warning", "No signature found in the response.")
                return

            signature = base64.b64decode(signature_b64)

            content = self.canonicalize_element(sign_target)

            self.verifying_certificate.public_key().verify(
                signature,
                content,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            QMessageBox.information(self, "Signature Verified", "The response signature is valid.")
        except Exception as e:
            QMessageBox.critical(self, "Signature Verification Failed", f"Verification error: {str(e)}")

    def send_request(self):
        if not self.client:
            QMessageBox.warning(self, "Warning", "Please import a WSDL first.")
            return
        try:
            xml_content = self.request_edit.toPlainText()
            root = ET.fromstring(xml_content)

            # Verify signature if a verifying certificate is provided
            if self.verifying_certificate:
                parent_map = {c: p for p in root.iter() for c in p}
                for elem in root.iter('Signature'):
                    parent = parent_map.get(elem)
                    if parent is None:
                        QMessageBox.warning(self, "Warning", "Signature element has no parent.")
                        return
                    signature_b64 = elem.text
                    if signature_b64:
                        signature = base64.b64decode(signature_b64)
                        content = ET.tostring(parent, encoding='utf-8', method='xml')
                        try:
                            self.verifying_certificate.public_key().verify(
                                signature,
                                content,
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                        except Exception:
                            QMessageBox.warning(self, "Warning", "Signature verification failed.")
                            return

            # Extract the operation name from the WSDL
            operation_name = list(self.client.service._operations.keys())[0]
            operation = list(self.client.service._operations.values())[0]

            # Parse the body content to extract operation parameters
            body = root.find('{http://schemas.xmlsoap.org/soap/envelope/}Body')
            if body is None:
                raise ValueError("SOAP Body not found in request XML.")

            # Get the operation element (first child of body)
            operation_elem = list(body)[0]
            if operation_elem.tag.split('}')[-1] != operation_name:
                raise ValueError(f"Expected operation {operation_name}, found {operation_elem.tag.split('}')[-1]}.")

            # Convert XML to a dictionary for zeep
            def xml_to_dict(elem):
                result = {}
                for child in elem:
                    child_name = child.tag.split('}')[-1]
                    if len(list(child)) > 0:
                        result[child_name] = xml_to_dict(child)
                    else:
                        result[child_name] = child.text or ''
                return result

            params = xml_to_dict(operation_elem)

            # Send the request using zeep's operation call
            response = self.client.service[operation_name](**params)

            # Convert response to XML
            response_dict = zeep.helpers.serialize_object(response, target_cls=dict)
            response_xml = self.dict_to_xml(response_dict, operation_name + 'Response')
            formatted_response = self.format_xml(response_xml)
            self.response_edit.setText(formatted_response)
            self.verify_response_signature(response_xml=formatted_response)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send request: {str(e)}")

    def dict_to_xml(self, data, root_tag):
        """Convert a dictionary to an XML string."""
        root = ET.Element(root_tag)
        def build_element(parent, key, value):
            if isinstance(value, dict):
                elem = ET.SubElement(parent, key)
                for k, v in value.items():
                    build_element(elem, k, v)
            elif isinstance(value, list):
                for item in value:
                    build_element(parent, key, item)
            else:
                elem = ET.SubElement(parent, key)
                elem.text = str(value) if value is not None else ''
        for key, value in data.items():
            build_element(root, key, value)
        return ET.tostring(root, encoding='unicode', method='xml')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SoapTester()
    window.show()
    sys.exit(app.exec())