import {validRequest} from './protocol.js';
chrome.runtime.onMessage.addListener((request,sender,reply)=>{
  // No content scripts/external messages: only this extension's own popup.
  if(sender.id!==chrome.runtime.id||sender.tab||!sender.url?.startsWith(chrome.runtime.getURL(''))||!validRequest(request)){
    reply({error:'許可されていない検査要求です。',release_authorized:false});return false;
  }
  chrome.runtime.sendNativeMessage('com.reachmade.aisecure',request,result=>{
    if(chrome.runtime.lastError){reply({error:'端末内の検査サービスへ接続できません。',release_authorized:false,browser_enforcement:false});return;}
    reply(result);
  });return true;
});
