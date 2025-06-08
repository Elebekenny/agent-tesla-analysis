
rule AgentTesla_Generic
{
    meta:
        description = "Detects Agent Tesla variant"
        author = "@elebekenny"
    strings:
        $s1 = "smtp.gmail.com"
        $s2 = "user=admin&pass="
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
