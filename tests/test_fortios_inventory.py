import json
import socket
import unittest
from unittest.mock import patch
from aisecure.providers.fortios_inventory import collect,parse_status,DeviceHTTPS,STATUS_PATH
from aisecure.gateway import GatewayError


class FortiOSInventoryTests(unittest.TestCase):
    def test_only_allowed_metadata_is_retained(self):
        result=parse_status({'status':'success','http_method':'GET','version':'v7.4.4','serial':'private-serial','results':{'hostname':'private-host'}},'vpn-1')
        self.assertEqual(result['assets'][0]['version'],'7.4.4')
        self.assertIsNone(result['assets'][0]['internet_exposed'])
        self.assertNotIn('private',json.dumps(result))
    def test_unknown_version_kept_unknown(self):
        self.assertEqual(parse_status({'status':'success','http_method':'GET','version':'custom-build'},'vpn-1')['assets'][0]['version'],'unknown')
    def test_failed_or_write_response_rejected(self):
        for value in [{'status':'error','http_method':'GET'},{'status':'success','http_method':'POST'}]:
            with self.assertRaises(GatewayError):parse_status(value,'vpn-1')
    def test_collector_only_gets_fixed_path(self):
        with patch('aisecure.providers.fortios_inventory.DeviceHTTPS') as cls:
            response=cls.return_value.getresponse.return_value;response.status=200
            response.read.return_value=json.dumps({'status':'success','http_method':'GET','version':'v7.4.4'}).encode()
            collect('vpn.example','test-read-only-token-000','vpn-1')
            args=cls.return_value.request.call_args
            self.assertEqual(args.args,('GET',STATUS_PATH))
            self.assertNotIn('access_token',args.args[1])
    def test_redirect_does_not_forward_token(self):
        with patch('aisecure.providers.fortios_inventory.DeviceHTTPS') as cls:
            response=cls.return_value.getresponse.return_value;response.status=302;response.read.return_value=b'private'
            with self.assertRaises(GatewayError):collect('vpn.example','test-read-only-token-000','vpn-1')
            self.assertEqual(cls.return_value.request.call_count,1)
    def test_metadata_address_is_not_contacted(self):
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('169.254.169.254',443))]),patch('socket.socket') as s:
            with self.assertRaises(GatewayError):DeviceHTTPS('vpn.example').connect()
            s.assert_not_called()
