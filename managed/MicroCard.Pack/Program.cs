using System.Text.Json;
using System.Security.Cryptography;
using MicroCard.Build;
if(args.Length!=8||args[7]!="--explicit-sign") { Console.Error.WriteLine("usage: MicroCard.Pack IMAGE METADATA DOMAIN INCARNATION_HEX VERSION SEED OUTPUT --explicit-sign"); return 2; }
static void ValidateStorage(JsonElement storage) {
 var count=0;var previous=-1;
 foreach(var declaration in storage.EnumerateArray()) {
  if(++count>64)throw new Exception("Persistent storage declaration quota exceeded");
  var key=declaration.GetProperty("key").GetInt32();var kind=declaration.GetProperty("kind").GetInt32();var maxBytes=declaration.GetProperty("max_bytes").GetInt32();
  if(key<0||key<=previous||kind==1&&maxBytes!=0||kind==2&&(maxBytes<1||maxBytes>2048)||kind is not (1 or 2))throw new Exception("Invalid persistent storage schema");
  previous=key;
 }
}
byte[]? seed=null;
try {
 var image=File.ReadAllBytes(args[0]);using var meta=JsonDocument.Parse(File.ReadAllBytes(args[1]));var root=meta.RootElement;
 var assembly=root.GetProperty("assembly").GetString();var dependencies=root.GetProperty("dependencies");if(!EmbeddedIdentifier.IsValid(args[2])||!EmbeddedIdentifier.IsValid(assembly)||dependencies.EnumerateArray().Any(value=>!EmbeddedIdentifier.IsValid(value.GetProperty("assembly").GetString())))throw new Exception("Domain, assembly, and dependencies must use the embedded identifier grammar");
 ValidateStorage(root.GetProperty("storage"));
 var incarnation=Convert.FromHexString(args[3]);if(incarnation.Length!=16)throw new Exception("Incarnation must be 16 bytes");
 var version=uint.Parse(args[4]);if(version==0)throw new Exception("Version starts at 1");
 using var manifest=new MemoryStream();using(var j=new Utf8JsonWriter(manifest,new JsonWriterOptions{Encoder=System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping})) {
  j.WriteStartObject();j.WriteString("domain",args[2]);j.WriteStartArray("incarnation");foreach(var b in incarnation)j.WriteNumberValue(b);j.WriteEndArray();j.WriteString("assembly",assembly);j.WritePropertyName("assembly_version");root.GetProperty("assembly_version").WriteTo(j);j.WriteNumber("version",version);j.WritePropertyName("export");root.GetProperty("export").WriteTo(j);
  j.WriteStartArray("entry_points");foreach(var a in root.GetProperty("entry_points").EnumerateArray()){j.WriteStartObject();j.WriteString("aid",a.GetProperty("aid").GetString());foreach(var field in new[]{"process","install","uninstall","select","deselect"}){j.WritePropertyName(field);a.GetProperty(field).WriteTo(j);}j.WriteEndObject();}j.WriteEndArray();
  foreach(var name in new[]{"dependencies","capabilities","storage"}){j.WritePropertyName(name);root.GetProperty(name).WriteTo(j);}
  j.WriteStartObject("limits");j.WriteNumber("arena",16384);j.WriteNumber("stack",256);j.WriteNumber("frames",32);j.WriteNumber("instructions",100000);j.WriteEndObject();j.WriteEndObject();
 }
 seed=File.ReadAllBytes(args[5]);if(seed.Length!=32)throw new Exception("P-256 seed must be 32 bytes");
 using var document=JsonDocument.Parse(manifest.ToArray());
 var package=PackageEnvelope.Create(ManifestCbor.Encode(document.RootElement),image,seed);
 File.WriteAllBytes(args[6],package);return 0;
} catch(Exception e){Console.Error.WriteLine(e.Message);return 1;} finally {if(seed!=null)CryptographicOperations.ZeroMemory(seed);}
