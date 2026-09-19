export function validRequest(value){
  if(!value||typeof value!=='object'||Array.isArray(value)||!/^[a-f0-9]{32}$/.test(value.request_id||''))return false;
  const keys=Object.keys(value).sort().join(',');
  if(value.action==='inspect_text')return keys==='action,request_id,text'&&typeof value.text==='string'&&new TextEncoder().encode(value.text).length<=262144;
  if(value.action!=='inspect_files'||keys!=='action,files,request_id'||!Array.isArray(value.files)||value.files.length<1||value.files.length>4)return false;
  let length=0;
  for(const file of value.files){if(!file||Object.keys(file).sort().join(',')!=='base64,format'||!['xlsx','pptx','pdf'].includes(file.format)||typeof file.base64!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(file.base64))return false;length+=file.base64.length;}
  return length<=Math.ceil(16*1024*1024/3)*4+16;
}
