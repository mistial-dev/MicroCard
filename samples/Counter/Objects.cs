public sealed class Cell { public int Value; public Cell(int value) { Value=value; } public int Add(int value){ Value+=value; return Value; } }
public static class Fixtures {
 public static int Remainder(int a,int b){return a%b;}
 public static int Divide(int a,int b){return a/b;}
 public static int Object(int x) { var c=new Cell(x); return c.Add(7); }
 public static int Array(int x) { var a=new int[3]; a[1]=x; return a[1]+a.Length; }
 public static int Bytes(int x) { var a=new byte[2]; a[1]=(byte)x; return a[1]; }
 public static int EmptyBytes() { byte[] a=[]; return a.Length; }
 public static int EmptyIntegers() { int[] a=[]; return a.Length; }
 public static int CollectionBytes(int x) { byte[] a=[1,(byte)x,3]; return a[1]+a.Length; }
 public static int CollectionIntegers(int x) { int[] a=[1,x,3]; return a[1]+a.Length; }
 public static int UnsignedDivide(int a,int b) { return unchecked((int)((uint)a/(uint)b)); }
 public static int UnsignedRemainder(int a,int b) { return unchecked((int)((uint)a%(uint)b)); }
 public static int UnsignedLess(int a,int b) { return (uint)a<(uint)b?1:0; }
 public static int UnsignedGreater(int a,int b) { return (uint)a>(uint)b?1:0; }
 public static int UnsignedCheckedAdd(int a,int b) { return unchecked((int)checked((uint)a+(uint)b)); }
 public static int CheckedByte(int x) { return checked((byte)x); }
 public static int CheckedSByte(int x) { return checked((sbyte)x); }
 public static int CheckedShort(int x) { return checked((short)x); }
 public static int CheckedUShort(int x) { return checked((ushort)x); }
 static uint AsUInt(int x) { return unchecked((uint)x); }
 public static int UnsignedThroughCall(int x) { return unchecked((int)AsUInt(x)); }
 public static int BitwiseNot(int x) { return ~x; }
 public static int Branch(int x) { if(x>5)return 7; return 3; }
 public static int Switch(int x) { switch(x){case 0:return 9;case 1:return 3;case 2:return 8;case 3:return 2;case 4:return 1;default:return 4;} }
}
