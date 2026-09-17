using System.Text.Json;
var results=new List<object>();
foreach(int x in new[]{-1000,-1,0,1,2,3,4,5,6,260,1000}) {
 foreach(var pair in new (string Name,Func<int,int> Fn)[]{("Object",Fixtures.Object),("Array",Fixtures.Array),("Bytes",Fixtures.Bytes),("CollectionBytes",Fixtures.CollectionBytes),("CollectionIntegers",Fixtures.CollectionIntegers),("Branch",Fixtures.Branch),("Switch",Fixtures.Switch)})
 results.Add(new {type="Fixtures",method=pair.Name,args=new[]{x},expected=pair.Fn(x)});
 results.Add(new {type="Counter",method="Arithmetic",args=new[]{x,7},expected=Counter.Arithmetic(x,7)});
}
results.Add(new {type="Fixtures",method="EmptyBytes",args=Array.Empty<int>(),expected=Fixtures.EmptyBytes()});
results.Add(new {type="Fixtures",method="EmptyIntegers",args=Array.Empty<int>(),expected=Fixtures.EmptyIntegers()});
foreach(var (a,b) in new[]{(int.MinValue,-1),(int.MinValue,1),(10,0),(-10,6),(10,-6)}) {
 foreach(var pair in new (string Name,Func<int,int,int> Fn)[]{("Remainder",Fixtures.Remainder),("Divide",Fixtures.Divide)}) {
 try {results.Add(new {type="Fixtures",method=pair.Name,args=new[]{a,b},expected=(int?)pair.Fn(a,b),error=(string)null});}
 catch(ArithmeticException){results.Add(new {type="Fixtures",method=pair.Name,args=new[]{a,b},expected=(int?)null,error="Arithmetic"});}
 }
}
foreach(var (a,b) in new[]{(-1,2),(int.MinValue,2),(10,0),(10,-1),(1,2)}) {
 foreach(var pair in new (string Name,Func<int,int,int> Fn)[]{("UnsignedDivide",Fixtures.UnsignedDivide),("UnsignedRemainder",Fixtures.UnsignedRemainder),("UnsignedCheckedAdd",Fixtures.UnsignedCheckedAdd)}) {
  try {results.Add(new {type="Fixtures",method=pair.Name,args=new[]{a,b},expected=(int?)pair.Fn(a,b),error=(string)null});}
  catch(ArithmeticException){results.Add(new {type="Fixtures",method=pair.Name,args=new[]{a,b},expected=(int?)null,error="Arithmetic"});}
 }
 results.Add(new {type="Fixtures",method="UnsignedLess",args=new[]{a,b},expected=Fixtures.UnsignedLess(a,b)});
 results.Add(new {type="Fixtures",method="UnsignedGreater",args=new[]{a,b},expected=Fixtures.UnsignedGreater(a,b)});
}
foreach(int x in new[]{int.MinValue,-32769,-32768,-129,-128,-1,0,127,128,255,256,32767,32768,65535,65536,int.MaxValue}) {
 foreach(var pair in new (string Name,Func<int,int> Fn)[]{("CheckedByte",Fixtures.CheckedByte),("CheckedSByte",Fixtures.CheckedSByte),("CheckedShort",Fixtures.CheckedShort),("CheckedUShort",Fixtures.CheckedUShort)}) {
  try {results.Add(new {type="Fixtures",method=pair.Name,args=new[]{x},expected=(int?)pair.Fn(x),error=(string)null});}
  catch(ArithmeticException){results.Add(new {type="Fixtures",method=pair.Name,args=new[]{x},expected=(int?)null,error="Arithmetic"});}
 }
 results.Add(new {type="Fixtures",method="UnsignedThroughCall",args=new[]{x},expected=Fixtures.UnsignedThroughCall(x)});
}
foreach(int x in new[]{-1000,-1,0,1,2,3,4,5,6,260,1000})
 results.Add(new {type="Fixtures",method="BitwiseNot",args=new[]{x},expected=Fixtures.BitwiseNot(x)});
Console.WriteLine(JsonSerializer.Serialize(results));
