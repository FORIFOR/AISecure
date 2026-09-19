import base64,io,secrets,tempfile,zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from aisecure.gateway import Evidence
from aisecure.control.audit import Audit

def keypair():
    k=Ed25519PrivateKey.generate()
    return (k.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()),k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
def office(fmt='xlsx',text='Public information',extra=None,hidden=False):
    from xml.sax.saxutils import escape
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
        main='xl/workbook.xml' if fmt=='xlsx' else 'ppt/presentation.xml'
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml' if fmt=='xlsx' else 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'
        z.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/'+main+'" ContentType="'+mimetype+'"/></Types>')
        z.writestr('_rels/.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="'+main+'"/></Relationships>')
        if fmt=='xlsx':
            z.writestr('xl/workbook.xml','<workbook><sheets><sheet state="'+('hidden' if hidden else 'visible')+'"/></sheets></workbook>')
            z.writestr('xl/worksheets/sheet1.xml','<worksheet><c><v>'+escape(text)+'</v></c></worksheet>')
        else:
            z.writestr('ppt/presentation.xml','<presentation/>')
            z.writestr('ppt/slides/slide1.xml','<sld><t>'+escape(text)+'</t></sld>')
        for k,v in (extra or {}).items():z.writestr(k,v)
    return b.getvalue()
def pdf(text='Public report',blank=False,encrypted=False,js=False,image=False):
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject,NameObject,DecodedStreamObject,ArrayObject,TextStringObject,NumberObject
    w=PdfWriter();page=w.add_blank_page(width=612,height=792)
    if not blank:
        font=DictionaryObject({NameObject('/Type'):NameObject('/Font'),NameObject('/Subtype'):NameObject('/Type1'),NameObject('/BaseFont'):NameObject('/Helvetica')})
        page[NameObject('/Resources')]=DictionaryObject({NameObject('/Font'):DictionaryObject({NameObject('/F1'):font})})
        stream=DecodedStreamObject();stream.set_data(('BT /F1 12 Tf 72 720 Td ('+text+') Tj ET').encode())
        page[NameObject('/Contents')]=w._add_object(stream)
    if image:
        obj=DecodedStreamObject();obj.set_data(b'\x00');obj.update({NameObject('/Subtype'):NameObject('/Image'),NameObject('/Width'):NumberObject(1),NameObject('/Height'):NumberObject(1)})
        page[NameObject('/TestImage')]=w._add_object(obj)
    if js:w.add_js('app.alert("test")')
    if encrypted:w.encrypt('synthetic-only')
    out=io.BytesIO();w.write(out);return out.getvalue()
def files(data=None,fmt='xlsx'):return [{'format':fmt,'base64':base64.b64encode(data or office(fmt)).decode()}]
class Store:
    def __enter__(self):
        self.temp=tempfile.TemporaryDirectory();self.evidence=Evidence(self.temp.name,b'k'*32)
        self.audit=Audit(self.evidence,b'k'*32);return self
    def __exit__(self,*args):self.evidence.close();self.temp.cleanup()
