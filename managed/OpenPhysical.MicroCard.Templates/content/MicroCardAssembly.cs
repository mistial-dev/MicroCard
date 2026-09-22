using MicroCard.Framework;

[CardAssembly("MicroCardAssemblyAid")]
public static class MicroCardAssembly
{
    public static void Install() { }

    public static void Select() { }

    public static void Deselect() { }

    public static void Process()
    {
        AssemblyContext.Current.Response.SetStatus(StatusWord.Success);
    }

    public static void Uninstall() { }
}
