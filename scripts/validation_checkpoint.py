"""Full host acceptance sequence. Invoked through check.py."""
import hashlib,json,pathlib,re,subprocess,os
from validation_common import ROOT, run
from analyzer_cases import run_analyzer_cases

def run_checkpoint():
 run('python3','scripts/mc04_inspector_test.py')
 run('python3','scripts/domain_inventory_test.py')
 run('python3','scripts/refresh_embedded_fixtures.py','--check')
 # The exhaustive journal power-cut sweep is intentionally byte-granular.
 run('cargo','test','--locked','--release')
 for project in ['managed/MicroCard.Analyzers','managed/MicroCard.Tool','managed/MicroCard.Pack','managed/MicroCard.Bundle','managed/MicroCard.Iso7816','managed/MicroCard.Encoding','managed/MicroCard.Cryptography','managed/MicroCard.Security','samples/CoreLib','samples/CoreConsumer','samples/Counter','samples/TransactionRecords','samples/KeyOperations','samples/Kdf108','samples/Kdf108Consumer','samples/Iso7816Consumer','samples/EncodingConsumer','samples/CryptographyConsumer','samples/SecurityConsumer','samples/Credential','samples/SigningAcceptance','tests/Reference','tests/CoreReference','tests/Kdf108Reference','tests/Iso7816Reference','tests/EncodingReference','tests/CryptographyReference','tests/AnalyzerCases','tests/TransactionRuntimeNegative','tests/VersionConstraints']:run('dotnet','build',project,'-c','Release','--nologo','--verbosity','quiet','-p:NuGetAudit=false')
 run('dotnet',str(ROOT/'tests/Iso7816Reference/bin/Release/net10.0/MicroCard.Iso7816.Tests.dll'))
 run('dotnet',str(ROOT/'tests/EncodingReference/bin/Release/net10.0/MicroCard.Encoding.Tests.dll'))
 run('dotnet',str(ROOT/'tests/CoreReference/bin/Release/net10.0/MicroCard.Core.Tests.dll'))
 run('dotnet',str(ROOT/'tests/CryptographyReference/bin/Release/net10.0/MicroCard.Cryptography.Tests.dll'))
 packages=ROOT/'work/packages';packages.mkdir(parents=True,exist_ok=True)
 run('dotnet','pack','managed/MicroCard.Analyzers','-c','Release','--no-build','--nologo','--output',str(packages))
 run('dotnet','restore','tests/AnalyzerBridge','--source',str(packages),'--packages',str(ROOT/'work/nuget-packages'),'--nologo','--force-evaluate')
 run('dotnet','pack','tests/AnalyzerBridge','-c','Release','--nologo','--no-restore','--output',str(packages))
 run('dotnet','restore','tests/AnalyzerPackageConsumer','--source',str(packages),'--packages',str(ROOT/'work/nuget-packages'),'--nologo','--force-evaluate')
 run('dotnet','build','tests/AnalyzerPackageConsumer','-c','Release','--no-restore','--nologo','--verbosity','quiet')
 packaged_bad=subprocess.run(['dotnet','build','tests/AnalyzerPackageConsumer','-c','Release','-t:Rebuild','--no-restore','--nologo','--verbosity','quiet','-p:MicroCardInvalidPackageCase=true'],cwd=ROOT,capture_output=True,text=True)
 assert packaged_bad.returncode!=0 and 'MCA0002' in packaged_bad.stdout,(packaged_bad.stdout,packaged_bad.stderr)
 run('dotnet',str(ROOT/'tests/VersionConstraints/bin/Release/net10.0/VersionConstraints.dll'))
 run_analyzer_cases()
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet')
 framework=ROOT/'managed/MicroCard.Framework/bin/Release/net10.0/MicroCard.Framework.dll';pin=hashlib.sha256(framework.read_bytes()).hexdigest()
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_PARAMETERS_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 parameter_boundary_prefix=ROOT/'work/parameter-boundary'
 for suffix in ('.mca','.json','.map.json'): parameter_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(parameter_boundary_prefix),str(framework),pin)
 assert parameter_boundary_prefix.with_suffix('.mca').exists(),'32-parameter boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_DEPENDENCY_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 dependency_boundary_prefix=ROOT/'work/dependency-boundary'
 for suffix in ('.mca','.json','.map.json'): dependency_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(dependency_boundary_prefix),str(framework),pin)
 assert dependency_boundary_prefix.with_suffix('.mca').exists(),'16-dependency boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_ENTRY_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 entry_boundary_prefix=ROOT/'work/entry-boundary'
 for suffix in ('.mca','.json','.map.json'): entry_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(entry_boundary_prefix),str(framework),pin)
 assert entry_boundary_prefix.with_suffix('.mca').exists(),'four-entry boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_METHOD_ROWS_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 method_boundary_prefix=ROOT/'work/method-row-boundary'
 for suffix in ('.mca','.json','.map.json'): method_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(method_boundary_prefix),str(framework),pin)
 assert method_boundary_prefix.with_suffix('.mca').exists(),'256-method boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_TYPE_ROWS_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 type_boundary_prefix=ROOT/'work/type-row-boundary'
 for suffix in ('.mca','.json','.map.json'): type_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(type_boundary_prefix),str(framework),pin)
 assert type_boundary_prefix.with_suffix('.mca').exists(),'253-TypeDef boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_FIELD_ROWS_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 field_boundary_prefix=ROOT/'work/field-row-boundary'
 for suffix in ('.mca','.json','.map.json'): field_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(field_boundary_prefix),str(framework),pin)
 assert field_boundary_prefix.with_suffix('.mca').exists(),'1022-FieldDef boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_ATTRIBUTE_ROWS_BOUNDARY','-p:MicroCardDisableAnalyzer=true')
 attribute_boundary_prefix=ROOT/'work/attribute-row-boundary'
 for suffix in ('.mca','.json','.map.json'): attribute_boundary_prefix.with_suffix(suffix).unlink(missing_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(attribute_boundary_prefix),str(framework),pin)
 assert attribute_boundary_prefix.with_suffix('.mca').exists(),'256-CustomAttribute boundary did not produce an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet')
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_TRANSACTION_CONSTRUCTOR','-p:MicroCardDisableAnalyzer=true')
 unsafe_prefix=ROOT/'work/unsafe-transaction'
 for suffix in ('.mca','.json','.map.json'): unsafe_prefix.with_suffix(suffix).unlink(missing_ok=True)
 unsafe=subprocess.run(['dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(unsafe_prefix),str(framework),pin],cwd=ROOT,capture_output=True,text=True)
 assert unsafe.returncode!=0 and 'Transactional method reaches irreversible Hardware.Write' in unsafe.stderr+unsafe.stdout,(unsafe.stdout,unsafe.stderr)
 assert not unsafe_prefix.with_suffix('.mca').exists(),'unsafe transaction produced an assembly'
 explicit_prefix=ROOT/'work/unsafe-explicit-transaction'
 for suffix in ('.mca','.json','.map.json'): explicit_prefix.with_suffix(suffix).unlink(missing_ok=True)
 explicit=subprocess.run(['dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/TransactionRuntimeNegative/bin/Release/net10.0/TransactionRuntimeNegative.dll'),str(explicit_prefix),str(framework),pin],cwd=ROOT,capture_output=True,text=True)
 assert explicit.returncode!=0 and 'Transactional method reaches irreversible Hardware.Write' in explicit.stderr+explicit.stdout,(explicit.stdout,explicit.stderr)
 assert not explicit_prefix.with_suffix('.mca').exists(),'unsafe explicit transaction produced an assembly'
 for symbol,name,error in [('CASE_STORAGE_SCHEMA','storage-schema-bypass','Persistent byte maximum'),('CASE_SYSTEM_SHA256_OVERLOAD','system-sha256-overload-bypass','Unsupported System.Security.Cryptography member'),('CASE_SYSTEM_RNG_OVERLOAD','system-rng-overload-bypass','Unsupported System.Security.Cryptography member'),('CASE_ASYNC_METHOD','async-bypass','Nested type unsupported'),('CASE_USING_DECLARATION','using-bypass','MC04 exception handlers unsupported'),('CASE_TYPEOF','typeof-bypass','Unsupported MC04 CIL operand InlineTok'),('CASE_INIT_PROPERTY','init-property-bypass','Modified signatures unsupported'),('CASE_REF_RETURN','ref-return-bypass','By-reference signatures unsupported'),('CASE_STATIC_CONSTRUCTOR','static-constructor-bypass','Static constructor unsupported'),('CASE_INTERFACE','interface-bypass','Interfaces unsupported'),('CASE_NESTED_TYPE','nested-type-bypass','Nested type unsupported'),('CASE_STATIC_FIELD','static-field-bypass','Unsupported field flags'),('CASE_FIELD_TYPE','field-type-bypass','Only Int32 fields and constants supported'),('CASE_METHOD_IMPL_FLAGS','method-flags-bypass','Unsupported method flags'),('CASE_INHERITANCE','inheritance-bypass','Unsupported base type'),('CASE_LITERAL_FIELD_TYPE','literal-field-bypass','Only Int32 fields and constants supported'),('CASE_EVENT','event-bypass','Only Int32 fields and constants supported'),('CASE_STATIC_AUTO_PROPERTY','static-auto-property-bypass','Unsupported field flags'),('CASE_AUTO_PROPERTY_FIELD','auto-property-field-bypass','Only Int32 fields and constants supported'),('CASE_IDENTIFIER','identifier-bypass','embedded identifier grammar'),('CASE_PARAMETERS','parameters-bypass','Method parameter quota exceeded'),('CASE_DEPENDENCY_LIMIT','dependency-limit-bypass','Dependency quota exceeded'),('CASE_ENTRY_LIMIT','entry-limit-bypass','Entry-point quota exceeded'),('CASE_METHOD_ROWS_LIMIT','method-row-limit-bypass','MC04 metadata row quota exceeded'),('CASE_TYPE_ROWS_LIMIT','type-row-limit-bypass','MC04 metadata row quota exceeded'),('CASE_FIELD_ROWS_LIMIT','field-row-limit-bypass','MC04 metadata row quota exceeded'),('CASE_ATTRIBUTE_ROWS_LIMIT','attribute-row-limit-bypass','MC04 custom attribute quota exceeded')]:
  run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet',f'-p:MicroCardAnalyzerCase={symbol}','-p:MicroCardDisableAnalyzer=true')
  prefix=ROOT/'work'/name
  for suffix in ('.mca','.json','.map.json'): prefix.with_suffix(suffix).unlink(missing_ok=True)
  rejected=subprocess.run(['dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(prefix),str(framework),pin],cwd=ROOT,capture_output=True,text=True)
  assert rejected.returncode!=0 and error in rejected.stderr+rejected.stdout,(symbol,rejected.stdout,rejected.stderr)
  assert not prefix.with_suffix('.mca').exists(),f'{symbol} produced an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_LOCALS','-p:MicroCardDisableAnalyzer=true')
 local_prefix=ROOT/'work/excessive-locals'
 for suffix in ('.mca','.json','.map.json'): local_prefix.with_suffix(suffix).unlink(missing_ok=True)
 excessive=subprocess.run(['dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(local_prefix),str(framework),pin],cwd=ROOT,capture_output=True,text=True)
 assert excessive.returncode!=0 and 'MC04 local-variable quota exceeded' in excessive.stderr+excessive.stdout,(excessive.stdout,excessive.stderr)
 assert not local_prefix.with_suffix('.mca').exists(),'excessive locals produced an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet','-p:MicroCardAnalyzerCase=CASE_SWITCH_LIMIT','-p:MicroCardDisableAnalyzer=true')
 switch_prefix=ROOT/'work/excessive-switch'
 for suffix in ('.mca','.json','.map.json'): switch_prefix.with_suffix(suffix).unlink(missing_ok=True)
 excessive_switch=subprocess.run(['dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(switch_prefix),str(framework),pin],cwd=ROOT,capture_output=True,text=True)
 assert excessive_switch.returncode!=0 and 'Switch quota' in excessive_switch.stderr+excessive_switch.stdout,(excessive_switch.stdout,excessive_switch.stderr)
 assert not switch_prefix.with_suffix('.mca').exists(),'excessive switch produced an assembly'
 run('dotnet','build','tests/AnalyzerCases','-c','Release','-t:Rebuild','--nologo','--verbosity','quiet')
 common=['dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/Counter/bin/Release/net10.0/Counter.dll')]
 for prefix in ['counter','counter-again']:run(*common,str(ROOT/'work'/prefix),str(framework),pin)
 counter_metadata=json.loads((ROOT/'work/counter.json').read_text());assert counter_metadata['storage']==[{'key':1,'kind':1,'max_bytes':0}]
 pack_tool=ROOT/'managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll';pack_seed=ROOT/'work/pack-quota.seed';pack_seed.write_bytes(bytes([0x5a])*32)
 large_image=ROOT/'work/pack-large.mca';large_image.write_bytes((ROOT/'work/counter.mca').read_bytes().ljust(9000,b'\0'))
 large_package=ROOT/'work/pack-large.mcp';run('dotnet',str(pack_tool),str(large_image),str(ROOT/'work/counter.json'),'quota','00'*16,'1',str(pack_seed),str(large_package),'--explicit-sign')
 assert 8192 < large_package.stat().st_size <= 16384,'packager did not accept a package above the former 8 KiB limit'
 invalid_identifier_package=ROOT/'work/pack-invalid-identifier.mcp';invalid_identifier_package.unlink(missing_ok=True)
 invalid_identifier=subprocess.run(['dotnet',str(pack_tool),str(ROOT/'work/counter.mca'),str(ROOT/'work/counter.json'),'bad/domain','00'*16,'1',str(pack_seed),str(invalid_identifier_package),'--explicit-sign'],cwd=ROOT,capture_output=True,text=True)
 assert invalid_identifier.returncode!=0 and 'embedded identifier grammar' in invalid_identifier.stderr+invalid_identifier.stdout and not invalid_identifier_package.exists(),(invalid_identifier.stdout,invalid_identifier.stderr)
 invalid_dependency_metadata=ROOT/'work/pack-invalid-dependency.json';invalid_dependency=json.loads((ROOT/'work/counter.json').read_text());invalid_dependency['dependencies']=[{'assembly':'bad/name'}];invalid_dependency_metadata.write_text(json.dumps(invalid_dependency,separators=(',',':')))
 invalid_dependency_package=ROOT/'work/pack-invalid-dependency.mcp';invalid_dependency_package.unlink(missing_ok=True)
 invalid_dependency_result=subprocess.run(['dotnet',str(pack_tool),str(ROOT/'work/counter.mca'),str(invalid_dependency_metadata),'quota','00'*16,'1',str(pack_seed),str(invalid_dependency_package),'--explicit-sign'],cwd=ROOT,capture_output=True,text=True)
 assert invalid_dependency_result.returncode!=0 and 'embedded identifier grammar' in invalid_dependency_result.stderr+invalid_dependency_result.stdout and not invalid_dependency_package.exists(),(invalid_dependency_result.stdout,invalid_dependency_result.stderr)
 invalid_storage_metadata=ROOT/'work/pack-invalid-storage.json';invalid_storage=dict(counter_metadata);invalid_storage['storage']=[{'key':2,'kind':1,'max_bytes':0},{'key':1,'kind':1,'max_bytes':0}];invalid_storage_metadata.write_text(json.dumps(invalid_storage,separators=(',',':')))
 invalid_storage_package=ROOT/'work/pack-invalid-storage.mcp';invalid_storage_package.unlink(missing_ok=True)
 invalid_storage_result=subprocess.run(['dotnet',str(pack_tool),str(ROOT/'work/counter.mca'),str(invalid_storage_metadata),'quota','00'*16,'1',str(pack_seed),str(invalid_storage_package),'--explicit-sign'],cwd=ROOT,capture_output=True,text=True)
 assert invalid_storage_result.returncode!=0 and 'Invalid persistent storage schema' in invalid_storage_result.stderr+invalid_storage_result.stdout and not invalid_storage_package.exists(),(invalid_storage_result.stdout,invalid_storage_result.stderr)
 oversized_image=ROOT/'work/pack-oversized.mca';oversized_image.write_bytes(bytes(16384));oversized_package=ROOT/'work/pack-oversized.mcp';oversized_package.unlink(missing_ok=True)
 oversized=subprocess.run(['dotnet',str(pack_tool),str(oversized_image),str(ROOT/'work/counter.json'),'quota','00'*16,'1',str(pack_seed),str(oversized_package),'--explicit-sign'],cwd=ROOT,capture_output=True,text=True)
 assert oversized.returncode!=0 and 'Package exceeds 16 KiB quota' in oversized.stderr+oversized.stdout and not oversized_package.exists(),(oversized.stdout,oversized.stderr)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/CoreLib/bin/Release/net10.0/MicroCard.Core.dll'),str(ROOT/'work/mscorlib'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/CoreConsumer/bin/Release/net10.0/CoreConsumer.dll'),str(ROOT/'work/core-consumer'),str(framework),pin)
 core_manifest=json.loads((ROOT/'work/mscorlib.json').read_text())
 core_consumer_manifest=json.loads((ROOT/'work/core-consumer.json').read_text())
 assert core_manifest['assembly']=='mscorlib' and core_manifest['assembly_version']==[0,1,0,0]
 assert core_consumer_manifest['dependencies'][0]['assembly']=='mscorlib'
 core_consumer_inspection=json.loads(subprocess.run(['python3','scripts/mcinspect.py','work/core-consumer.mca'],cwd=ROOT,check=True,capture_output=True,text=True).stdout)
 assembly_references=[row['columns']['Name']['value'] for table in core_consumer_inspection['tables'] if table['name']=='AssemblyRef' for row in table['rows']]
 assert 'mscorlib' in assembly_references and 'MicroCard.Core' not in assembly_references
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/SigningAcceptance/bin/Release/net10.0/SigningAcceptance.dll'),str(ROOT/'work/signing-acceptance'),str(framework),pin)
 public_prefix=ROOT/'work/public-tool/counter';public_prefix.parent.mkdir(parents=True,exist_ok=True)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/Counter/bin/Release/net10.0/Counter.dll'),str(public_prefix),str(framework),pin)
 assert public_prefix.with_suffix('.mca').exists() and not public_prefix.with_suffix('.mci').exists(),'public preprocessor emitted a legacy assembly'
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/Kdf108/bin/Release/net10.0/Kdf108.dll'),str(ROOT/'work/kdf108'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/Kdf108Consumer/bin/Release/net10.0/Kdf108Consumer.dll'),str(ROOT/'work/kdf108-consumer'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'managed/MicroCard.Iso7816/bin/Release/net10.0/MicroCard.Iso7816.dll'),str(ROOT/'work/iso7816'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'managed/MicroCard.Encoding/bin/Release/net10.0/MicroCard.Encoding.dll'),str(ROOT/'work/encoding'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/EncodingConsumer/bin/Release/net10.0/EncodingConsumer.dll'),str(ROOT/'work/encoding-consumer'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'managed/MicroCard.Cryptography/bin/Release/net10.0/MicroCard.Cryptography.dll'),str(ROOT/'work/cryptography'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'managed/MicroCard.Security/bin/Release/net10.0/MicroCard.Security.dll'),str(ROOT/'work/security'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/SecurityConsumer/bin/Release/net10.0/SecurityConsumer.dll'),str(ROOT/'work/security-consumer'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/Credential/bin/Release/net10.0/Credential.dll'),str(ROOT/'work/credential'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/CryptographyConsumer/bin/Release/net10.0/CryptographyConsumer.dll'),str(ROOT/'work/cryptography-consumer'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/Iso7816Consumer/bin/Release/net10.0/Iso7816Consumer.dll'),str(ROOT/'work/iso7816-consumer'),str(framework),pin)
 iso_manifest=json.loads((ROOT/'work/iso7816.json').read_text())
 assert iso_manifest['assembly']=='MicroCard.Iso7816' and iso_manifest['capabilities']==[] and iso_manifest['entry_points']==[]
 encoding_manifest=json.loads((ROOT/'work/encoding.json').read_text())
 assert encoding_manifest['assembly']=='MicroCard.Encoding' and encoding_manifest['capabilities']==[] and encoding_manifest['entry_points']==[]
 encoding_consumer=json.loads((ROOT/'work/encoding-consumer.json').read_text())
 assert encoding_consumer['capabilities']==[2,11,12,13] and encoding_consumer['dependencies'][0]['assembly']=='MicroCard.Encoding'
 cryptography_manifest=json.loads((ROOT/'work/cryptography.json').read_text())
 assert cryptography_manifest['capabilities']==[20,22,23,24,25,26,27,28,29,30,35,36,37,38,39,49,50,51] and cryptography_manifest['entry_points']==[]
 security_manifest=json.loads((ROOT/'work/security.json').read_text())
 assert security_manifest['capabilities']==[40,41,42,43,44,45] and security_manifest['entry_points']==[]
 security_consumer=json.loads((ROOT/'work/security-consumer.json').read_text())
 assert security_consumer['capabilities']==[2,11,12,13,23] and security_consumer['dependencies'][0]['assembly']=='MicroCard.Security'
 cryptography_consumer=json.loads((ROOT/'work/cryptography-consumer.json').read_text())
 assert cryptography_consumer['capabilities']==[2,11,12,13,20,50] and cryptography_consumer['dependencies'][0]['assembly']=='MicroCard.Cryptography'
 iso_consumer=json.loads((ROOT/'work/iso7816-consumer.json').read_text())
 assert iso_consumer['capabilities']==[2,11,12,13] and iso_consumer['dependencies'][0]['assembly']=='MicroCard.Iso7816'
 iso_inspection=json.loads(subprocess.run(['python3','scripts/mcinspect.py','work/iso7816.mca'],cwd=ROOT,check=True,capture_output=True,text=True).stdout)
 assert 'Field' not in [table['name'] for table in iso_inspection['tables']],'compile-time constants leaked into MC04 metadata'
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/KeyOperations/bin/Release/net10.0/KeyOperations.dll'),str(ROOT/'work/keys'),str(framework),pin)
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'samples/TransactionRecords/bin/Release/net10.0/TransactionRecords.dll'),str(ROOT/'work/transaction-records'),str(framework),pin)
 assert (ROOT/'work/counter.mca').read_bytes()==(ROOT/'fuzz/fixtures/counter.mca').read_bytes(),'counter fuzz fixture is stale'
 assert (ROOT/'work/mscorlib.mca').read_bytes()==(ROOT/'fuzz/fixtures/mscorlib.mca').read_bytes(),'mscorlib fuzz fixture is stale'
 assert (ROOT/'work/keys.mca').read_bytes()==(ROOT/'fuzz/fixtures/key_operations.mca').read_bytes(),'key-operation transaction fixture is stale'
 assert (ROOT/'work/kdf108.mca').read_bytes()==(ROOT/'fuzz/fixtures/kdf108.mca').read_bytes(),'Kdf108 fuzz fixture is stale'
 assert (ROOT/'work/kdf108-consumer.mca').read_bytes()==(ROOT/'fuzz/fixtures/kdf108_consumer.mca').read_bytes(),'Kdf108 consumer fuzz fixture is stale'
 assert (ROOT/'work/cryptography.mca').read_bytes()==(ROOT/'fuzz/fixtures/cryptography.mca').read_bytes(),'cryptography fuzz fixture is stale'
 assert (ROOT/'work/cryptography-consumer.mca').read_bytes()==(ROOT/'fuzz/fixtures/cryptography_consumer.mca').read_bytes(),'cryptography consumer fuzz fixture is stale'
 assert (ROOT/'work/security.mca').read_bytes()==(ROOT/'fuzz/fixtures/security.mca').read_bytes(),'security runtime fixture is stale'
 assert (ROOT/'work/credential.mca').read_bytes()==(ROOT/'fuzz/fixtures/credential.mca').read_bytes(),'credential runtime fixture is stale'
 assert (ROOT/'work/transaction-records.mca').read_bytes()==(ROOT/'tests/fixtures/transaction_records.mca').read_bytes(),'transaction runtime fixture is stale'
 run('dotnet',str(ROOT/'managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll'),str(ROOT/'tests/AnalyzerCases/bin/Release/net10.0/AnalyzerCases.dll'),str(ROOT/'work/dependency'),str(framework),pin)
 dependency_assembly=(ROOT/'work/dependency.mca').read_bytes()
 assert b'EmptyCore\0' not in dependency_assembly and b'value\0' not in dependency_assembly,'private metadata name retained'
 assert b'Empty\0' in dependency_assembly and b'Read\0' in dependency_assembly,'public metadata name stripped'
 dependency=json.loads((ROOT/'work/dependency.json').read_text());assert dependency['export']=={'access':1,'key':None}
 declared=dependency['dependencies'];assert len(declared)==1 and declared[0]['assembly']=='mscorlib' and declared[0]['ranges']==[{'min':[1,2,0,0],'min_inclusive':True,'max':[1,3,0,0],'max_inclusive':False}] and declared[0]['signer']==[0]*32
 for ext in ['mca','json','map.json']:assert (ROOT/f'work/counter.{ext}').read_bytes()==(ROOT/f'work/counter-again.{ext}').read_bytes(),ext
 assert (ROOT/'work/counter.mca').stat().st_size < (ROOT/'samples/Counter/bin/Release/net10.0/Counter.dll').stat().st_size
 assert (ROOT/'work/counter.mca').stat().st_size <= 3072,'MC04 counter assembly exceeded 3 KiB regression budget'
 mapping=json.loads((ROOT/'work/counter.map.json').read_text())
 target=ROOT/'work/msbuild/counter'
 properties=['-p:MicroCardEnabled=true',f'-p:MicroCardFramework={framework}',f'-p:MicroCardFrameworkHash={pin}',f'-p:MicroCardTool={ROOT}/managed/MicroCard.Tool/bin/Release/net10.0/MicroCard.Tool.dll',f'-p:MicroCardOutput={target}']
 run('dotnet','build','samples/Counter','-c','Release','--nologo','--verbosity','quiet',*properties)
 stamp=target.with_suffix('.mca').stat().st_mtime_ns
 run('dotnet','build','samples/Counter','-c','Release','--nologo','--verbosity','quiet',*properties)
 assert target.with_suffix('.mca').stat().st_mtime_ns==stamp,'incremental output regenerated'
 bad=subprocess.run(['dotnet','build','samples/Counter','-c','Release','--nologo','--verbosity','quiet',*properties,'-p:MicroCardFrameworkHash=00'],cwd=ROOT,capture_output=True,text=True)
 assert bad.returncode!=0 and 'approved pin' in bad.stdout
 run('cargo','build','--locked','--quiet')
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/counter.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/mscorlib.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/iso7816.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/encoding.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/encoding-consumer.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/cryptography.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/cryptography-consumer.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/security.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/security-consumer.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/credential.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'work/transaction-records.mca'))
 run(str(ROOT/'target/debug/microcard-sim'),'verify-assembly',str(ROOT/'tests/fixtures/transaction_runtime_negative.mca'))
 run('python3','scripts/piv_vector_acceptance.py')
 run('python3','scripts/framework_identity_test.py')
 run('python3','scripts/mc04_output_test.py')
 run('python3','scripts/assembly_budgets.py','--check')
 run('python3','scripts/mc04_execute_test.py')
 run('python3','scripts/kdf108_acceptance.py')
 run('python3','scripts/iso7816_acceptance.py')
 run('python3','scripts/iso7816_acceptance.py',env={**os.environ,'MICROCARD_BINARY':'1'})
 run('python3','scripts/encoding_acceptance.py')
 run('python3','scripts/encoding_acceptance.py',env={**os.environ,'MICROCARD_BINARY':'1'})
 run('python3','scripts/cryptography_acceptance.py')
 run('python3','scripts/cryptography_acceptance.py',env={**os.environ,'MICROCARD_BINARY':'1'})
 run('python3','scripts/security_acceptance.py')
 run('python3','scripts/security_acceptance.py',env={**os.environ,'MICROCARD_BINARY':'1'})
 run('python3','scripts/default_bundle_acceptance.py')
 run('python3','scripts/core_library_acceptance.py')
 run('python3','scripts/credential_acceptance.py')
 print('PASS: deterministic MC04 preprocessing and managed differential execution')
 run('python3','scripts/scp03_acceptance.py')
 run('python3','scripts/scp03_acceptance.py',env={**os.environ,'MICROCARD_BINARY':'1'})
 run('python3','scripts/serial_adapter_test.py')
 run('python3','scripts/signing_acceptance.py')
 run('cargo','check','--manifest-path','fuzz/Cargo.toml','--bins','--locked')
 run('python3','scripts/board_budgets.py','--check')
