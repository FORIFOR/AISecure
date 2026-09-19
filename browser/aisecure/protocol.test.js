import test from 'node:test';import assert from 'node:assert/strict';import {validRequest} from './protocol.js';
const id='a'.repeat(32);
test('bounded text accepted',()=>assert.equal(validRequest({action:'inspect_text',text:'Hello',request_id:id}),true));
test('oversized text denied',()=>assert.equal(validRequest({action:'inspect_text',text:'x'.repeat(262145),request_id:id}),false));
test('URL or arbitrary path denied',()=>assert.equal(validRequest({action:'inspect_files',files:[{path:'/etc/passwd'}],request_id:id}),false));
test('caller permissions denied',()=>assert.equal(validRequest({action:'inspect_text',text:'ok',request_id:id,allow:true}),false));
test('executable extension denied',()=>assert.equal(validRequest({action:'inspect_files',files:[{format:'exe',base64:'AA=='}],request_id:id}),false));
test('valid file envelope',()=>assert.equal(validRequest({action:'inspect_files',files:[{format:'pdf',base64:'AA=='}],request_id:id}),true));
test('no arbitrary actions',()=>assert.equal(validRequest({action:'execute',text:'rm',request_id:id}),false));
