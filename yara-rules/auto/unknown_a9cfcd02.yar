import "hash"

rule AutoGen_Unknown_a9cfcd02_HashOnly
{
    meta:
        description = "Auto-generated hash-only rule for unknown_a9cfcd02 (no discriminating strings survived boilerplate filtering)"
        author      = "honeypot-bot"
        date        = "2026-07-31"
        auto_generated = true
        hash_only   = true
        sample_sha256 = "a9cfcd028a90c4fd525a8e29894194e9a4aecb90924a04618474e510405426c7"
        file_types  = "Text"
        reference1  = "https://www.virustotal.com/gui/file/a9cfcd028a90c4fd525a8e29894194e9a4aecb90924a04618474e510405426c7"
        reference2  = "https://bazaar.abuse.ch/sample//"

    condition:
        hash.sha256(0, filesize) == "a9cfcd028a90c4fd525a8e29894194e9a4aecb90924a04618474e510405426c7"
}
