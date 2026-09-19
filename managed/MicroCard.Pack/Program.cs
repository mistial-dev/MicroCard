using System.Text.Json;
using System.Security.Cryptography;
using MicroCard.Build;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
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
 var curve=SecNamedCurves.GetByName("secp256r1");var domain=new ECDomainParameters(curve.Curve,curve.G,curve.N);
 var d=new BigInteger(1,seed);if(d.SignValue<=0||d.CompareTo(curve.N)>=0)throw new Exception("Seed is not a P-256 private scalar");
 var q=curve.G.Multiply(d).Normalize();
 using var package=new MemoryStream();using var writer=new BinaryWriter(package);writer.Write("MP04"u8);writer.Write("MicroCard signed package v4\0"u8);writer.Write(checked((uint)manifest.Length));writer.Write(checked((uint)image.Length));writer.Write(manifest.ToArray());writer.Write(image);writer.Write(q.GetEncoded(false));
 var bytes=package.ToArray();writer.Write(Signature(new ECPrivateKeyParameters(d,domain),curve.N,bytes));if(package.Length>16384)throw new Exception("Package exceeds 16 KiB quota");File.WriteAllBytes(args[6],package.ToArray());return 0;
} catch(Exception e){Console.Error.WriteLine(e.Message);return 1;} finally {if(seed!=null)CryptographicOperations.ZeroMemory(seed);}

// Deterministic ECDSA over SHA-256, RFC 6979, emitted as fixed-width r and s.
// The card accepts only the low of the two signatures that verify, so that one signed
// package has one encoding and therefore one digest and one registry identity. Every
// packager in every language has to agree on this.
static byte[] Signature(ECPrivateKeyParameters key, BigInteger order, byte[] message) {
 var signer=new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
 signer.Init(true,key);
 var parts=signer.GenerateSignature(SHA256.HashData(message));
 var r=parts[0];var s=parts[1];
 if(s.CompareTo(order.ShiftRight(1))>0)s=order.Subtract(s);
 var output=new byte[64];
 Fixed(r).CopyTo(output,0);Fixed(s).CopyTo(output,32);
 return output;
}

static byte[] Fixed(BigInteger value) {
 var bytes=value.ToByteArrayUnsigned();
 if(bytes.Length>32)throw new Exception("ECDSA component exceeds 32 bytes");
 var padded=new byte[32];bytes.CopyTo(padded,32-bytes.Length);
 return padded;
}
