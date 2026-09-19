"""Synthetic metadata only. CVE-2099-99999 and LabVPN are fictitious."""
from datetime import datetime,timezone
import time

def seed(app):
    now=int(time.time());iso=datetime.fromtimestamp(now,timezone.utc).isoformat()
    posture={'inventory':{'observed_at':iso,'assets':[{'id':'lab-vpn','vendor':'Example','product':'LabVPN',
        'version':'1.1','internet_exposed':True,'privileged_path':True,'sensitive_path':True}]},
        'advisories':{'observed_at':iso,'advisories':[{'vendor':'Example','product':'LabVPN','cve':'CVE-2099-99999',
        'introduced':'1.0','fixed':'1.2','source':'https://example.invalid/synthetic-only'}]},
        'kev':{'dateReleased':iso,'vulnerabilities':[{'cveID':'CVE-2099-99999'}],'fetched_at':now},
        'controls':[{'asset_id':'lab-vpn','observed_at':now,'mfa_required':False,'admin_public':None,'supported':True}]}
    app.process('/api/posture',posture)
    events=[]
    def event(i,at,kind,**kwargs):
        return {'id':f'demo-{now}-{i}','at':at,'kind':kind,'actor':'synthetic-user','session':'synthetic-session',
                'asset':'lab-vpn','result':'success',**kwargs}
    events.append(event(1,now-1800,'vpn_login',channel='vpn',privileged=True,mfa=False,device_trusted=False))
    for i in range(2,7):events.append(event(i,now-1700+i,'file_read',channel='filesystem',data_class='confidential',target=f'file-{i}'))
    for i in range(7,10):events.append(event(i,now-1500+(i-7)*650,'egress',channel='ai',data_class='confidential',
                                            target='personal-ai',target_type='personal',bytes=1024))
    for value in events:app.events.ingest(value,organization=app.organization,source=app.source)
    return {'synthetic':True,'external_requests':0,'events':len(events),'device_changes':0}
