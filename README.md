# BunnySSTool

A screenshare / PC-checking tool **loader** for Minecraft.

Themed after *Rascal Does Not Dream of a Bunny Girl Senpai* (Seishun Buta Yarou).

BunnySSTool does not write any of the forensic tools itself. It fetches
each tool from its official source and launches it. Downloaded files are
organized under `%USERPROFILE%\Downloads\BunnySSTool\<Category>\<ToolName>\`.

## Requirements

- Windows 10/11
- PowerShell 5.1+
- .NET Framework

## Installation

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/kxzyyyy/BunnySSTool/main/BunnySSTool.ps1')"
```

## Tools included

| Tool                | Category     |
|---------------------|--------------|
| BAMReveal           | Orbdiff      |
| StringsParser       | Orbdiff      |
| INJgen              | Orbdiff      |
| Fileless            | Orbdiff      |
| JARParser           | Orbdiff      |
| CheckDeletedUSN     | Orbdiff      |
| USBDetector         | Orbdiff      |
| BAMDeletedKeys      | Spokwn       |
| pcasvc-executed     | Spokwn       |
| MeowClientFucker    | MeowTonynoh  |
| MeowModAnalyzer     | MeowTonynoh  |
| MeowResolver        | MeowTonynoh  |
| Services            | PraiseLilly  |
| RL ModAnalyzer      | RedLotus     |
| RL AltChecker       | RedLotus     |
| P1AE.Javaw          | Others       |
| MacroDetector       | Others       |
| DQRKIS-Fucker       | Others       |
| SystemInformer      | Others       |
| Luyten              | Others       |
| ToolsDownloader++   | Others       |


## Disclaimer

Every tool is developed and maintained by its own author. BunnySSTool
only downloads and launches them. The author of BunnySSTool takes no
responsibility for anything that may be found regarding these tools in
the future, nor for any consequences of their use.

Theme/character references belong to their respective rights holders;
this is a non-commercial fan project.
