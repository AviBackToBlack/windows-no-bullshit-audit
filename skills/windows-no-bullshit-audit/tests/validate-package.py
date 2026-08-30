from pathlib import Path
import re, sys
root=Path(__file__).resolve().parents[1]
skill=root/'SKILL.md'
text=skill.read_text(encoding='utf-8')
errs=[]
if not text.startswith('---\n'):
    errs.append('SKILL.md missing YAML frontmatter')
parts=text.split('---\n',2)
if len(parts)<3:
    errs.append('SKILL.md malformed frontmatter')
else:
    fm=parts[1]
    def field(name):
        m=re.search(rf'(?m)^{re.escape(name)}:\s*(.+)$',fm)
        return m.group(1).strip() if m else None
    name=field('name')
    desc=field('description')
    if not name: errs.append('missing name')
    if name and not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',name): errs.append(f'invalid name: {name}')
    if name and name != root.name: errs.append(f'name {name} != directory {root.name}')
    if name and len(name)>64: errs.append('name >64 chars')
    if not desc: errs.append('missing description')
    if desc and len(desc)>1024: errs.append('description >1024 chars')
if len(text.splitlines())>500:
    errs.append(f'SKILL.md >500 lines ({len(text.splitlines())})')
for rel in re.findall(r'\]\((references/[^)]+|assets/[^)]+|scripts/[^)]+)\)',text):
    if not (root/rel).exists(): errs.append(f'missing referenced file: {rel}')
required=['scripts/attest-target.ps1','references/target-attestation.md','scripts/collect-baseline.ps1','scripts/collect-autoruns.ps1','scripts/collect-performance.ps1','scripts/verify-after-repair.ps1','assets/audit-state.schema.json']
for rel in required:
    if not (root/rel).exists(): errs.append(f'missing required project resource: {rel}')
if errs:
    print('FAIL')
    for e in errs: print('-',e)
    sys.exit(1)
print('OK')
print('SKILL.md lines:',len(text.splitlines()))
print('Files:',sum(1 for p in root.rglob('*') if p.is_file()))
