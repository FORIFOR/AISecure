"""Build hashes and SPDX 2.3 inventory of this BUILD ENVIRONMENT.

This environment SBOM includes builder/test packages; it is not an assertion of
all transitive runtime dependencies in a deployment. No keys, fonts or user logs.
"""
from datetime import datetime,timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import uuid

out=Path('dist');out.mkdir(exist_ok=True)
packages=[]
for d in sorted(importlib.metadata.distributions(),key=lambda d:d.metadata['Name'].lower()):
    name=d.metadata['Name'];identifier='SPDXRef-Package-'+re.sub(r'[^a-zA-Z0-9.-]','-',name)
    packages.append({'name':name,'SPDXID':identifier,'versionInfo':d.version,'downloadLocation':'NOASSERTION',
                     'filesAnalyzed':False,'licenseConcluded':'NOASSERTION','licenseDeclared':'NOASSERTION','copyrightText':'NOASSERTION'})
bom={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'AISecure-build-environment',
     'documentNamespace':'https://github.com/FORIFOR/AISecure/sbom/'+str(uuid.uuid4()),
     'creationInfo':{'creators':['Tool: AISecure build_release.py'],'created':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
     'packages':packages,'relationships':[{'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':p['SPDXID']} for p in packages]}
(out/'build-environment.spdx.json').write_text(json.dumps(bom,indent=2))
(out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.is_file() and p.name!='SHA256SUMS.txt'))
print('Created build-environment SPDX inventory and artifact checksums')
