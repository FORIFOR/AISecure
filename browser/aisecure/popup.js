import {validRequest} from './protocol.js';
const $=id=>document.getElementById(id);
async function inspect(action){
  try{
    const request={action,request_id:crypto.randomUUID().replaceAll('-','')};
    if(action==='inspect_text')request.text=$('text').value;
    else{
      const selected=[...$('files').files];if(!selected.length||selected.length>4||selected.reduce((n,f)=>n+f.size,0)>16*1024*1024)throw Error('資料は1〜4件、合計16MiBまでです。');
      request.files=await Promise.all(selected.map(file=>new Promise((resolve,reject)=>{const reader=new FileReader();reader.onerror=reject;reader.onload=()=>resolve({format:file.name.split('.').pop().toLowerCase(),base64:reader.result.split(',')[1]});reader.readAsDataURL(file);})));}
    if(!validRequest(request))throw Error('検査形式を確認してください。');
    $('result').textContent='端末内で検査しています。';
    const result=await chrome.runtime.sendMessage(request);$('result').textContent=JSON.stringify(result,null,2);
  }catch(e){$('result').textContent=e.message||'検査を完了できませんでした。';}
}
$('inspect').onclick=()=>inspect('inspect_files');$('inspect-text').onclick=()=>inspect('inspect_text');
