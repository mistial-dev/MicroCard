# MicroCardAssembly

Build the assembly and convert it to MC04:

```sh
dotnet build
```

The converted files are written to
`obj/Debug/net10.0/microcard/MicroCardAssembly.{mca,json,map.json}`. With the MicroCard
host simulator on `PATH`, validate the device image with:

```sh
microcard-sim verify-assembly obj/Debug/net10.0/microcard/MicroCardAssembly.mca
```
