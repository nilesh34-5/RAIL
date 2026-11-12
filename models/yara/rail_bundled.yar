
rule EICAR_Test_File
{
    meta:
        description = "EICAR standard anti-malware test string"
        severity = "high"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Windows_PE_Executable
{
    meta:
        // Informational only: file typing is the file_type detector's job, so a
        // higher severity here would double-count the same evidence under the
        // Noisy-OR model, which assumes detectors are independent.
        description = "Windows PE executable marker (informational)"
        severity = "info"
    strings:
        $mz = "MZ"
        $dos = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $dos
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Encoded / obfuscated PowerShell often seen in droppers"
        severity = "medium"
    strings:
        $enc = "-enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $b64 = "FromBase64String" nocase
        $iex = "IEX(" nocase
    condition:
        2 of them
}

rule Script_In_Document
{
    meta:
        description = "Script tag or JS action embedded in a document object"
        severity = "medium"
    strings:
        $js1 = "/JavaScript"
        $js2 = "/OpenAction"
        $sh = "<script"
    condition:
        any of them
}

rule Embedded_Executable_Marker
{
    meta:
        description = "PE/ELF payload embedded inside a NON-executable carrier"
        severity = "medium"
    strings:
        $mz = "This program cannot be run in DOS mode"
        $elf = { 7F 45 4C 46 }
    condition:
        // Only fire when the carrier is not itself an executable. A normal PE
        // always contains the DOS stub string at ~offset 78, so testing merely
        // for its presence (or "not at 0") matches every legitimate binary.
        ($mz and uint16(0) != 0x5A4D)
        or ($elf in (64..filesize) and uint32(0) != 0x464C457F)
}
