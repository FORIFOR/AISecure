import {validRequest} from './protocol.js';
import {evaluateRequest, inspectedHost, MAX_TEXT} from './enforce.js';

const HOST_NAME='com.reachmade.aisecure';

function requestId(){return crypto.randomUUID().replaceAll('-','');}

/* The native host bounds text by UTF-8 length, so trim by bytes, not characters. */
function fit(text){
  const encoder=new TextEncoder();
  let value=text.slice(0,MAX_TEXT);
  while(encoder.encode(value).length>MAX_TEXT)value=value.slice(0,Math.floor(value.length*0.9));
  return value;
}

function nativeMessage(request){
  return new Promise(resolve=>{
    chrome.runtime.sendNativeMessage(HOST_NAME,request,result=>{
      if(chrome.runtime.lastError)resolve({error:'unreachable'});
      else resolve(result);
    });
  });
}

/* Explicit popup checks: unchanged, and still refused from any page. */
function fromOwnPopup(sender){
  return sender.id===chrome.runtime.id&&!sender.tab&&sender.url?.startsWith(chrome.runtime.getURL(''));
}

/* In-page enforcement: only from this extension's content scripts, only on the
   hosts the manifest injects into. The page itself cannot reach this. */
function fromInspectedPage(sender){
  if(sender.id!==chrome.runtime.id||!sender.tab)return false;
  try{return inspectedHost(new URL(sender.origin||sender.url||'').hostname);}catch{return false;}
}

chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(message?.action==='enforce_prompt'){
    if(!fromInspectedPage(sender)){
      reply({action:'block',reason:'unexpected_response',override:false});return false;
    }
    const {url,method,body,unreadable}=message.request||{};
    evaluateRequest({url,method,body:unreadable?null:body},async ({text})=>{
      const request={action:'inspect_text',text:fit(text),request_id:requestId()};
      if(!validRequest(request))return {error:'invalid_request'};
      return nativeMessage(request);
    }).then(reply,()=>reply({action:'block',reason:'inspection_unavailable',override:false}));
    return true;
  }
  // No content scripts/external messages: only this extension's own popup.
  if(!fromOwnPopup(sender)||!validRequest(message)){
    reply({error:'許可されていない検査要求です。',release_authorized:false});return false;
  }
  nativeMessage(message).then(result=>{
    if(result?.error==='unreachable')reply({error:'端末内の検査サービスへ接続できません。',release_authorized:false,browser_enforcement:false});
    else reply(result);
  });
  return true;
});
