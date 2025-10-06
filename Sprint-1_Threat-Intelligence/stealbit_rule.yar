rule StealBit_Generic_Detection
{
    meta:
        author = "Henriee"
        description = "Detects StealBit malware based on simple text strings and patterns"
        date = "2025-09-23"
        reference = "Group 3 Threat Intelligence Task"
        malware_family = "StealBit"
        threat_group = "LockBit"

    strings:
        // You can add known strings, keywords, or unique code fragments here
        // Example: function names, command-line arguments, or mutex names from analysis
        $name1 = "StealBit" nocase
        $name2 = "LockBit" nocase
        $keyword1 = "exfil" nocase        // Keyword indicating data exfiltration activity
        $keyword2 = "upload" nocase       // Optional: used in file transfer logic

        // Optional: Add hex patterns or unique strings found in malware binaries
        // Example:
        // $hex_pattern = { 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 }

    condition:
        // Adjust detection logic based on your needs:
        // This rule triggers if at least 2 of the listed strings are found in a file
        2 of ($name* or $keyword*)
}
