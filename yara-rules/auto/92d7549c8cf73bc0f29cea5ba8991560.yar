import "hash"

rule AutoGen_92d7549c8cf73bc0f29cea5ba8991560_HashOnly
{
    meta:
        description = "Auto-generated hash-only rule for 92d7549c8cf73bc0f29cea5ba8991560 (no discriminating strings survived boilerplate filtering)"
        author      = "honeypot-bot"
        date        = "2026-08-02"
        auto_generated = true
        hash_only   = true
        sample_sha256 = "6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
        file_types  = "Win32 DLL"
        reference1  = "https://www.virustotal.com/gui/file/6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
        reference2  = "https://bazaar.abuse.ch/sample/6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b/"

    condition:
        hash.sha256(0, filesize) == "6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
}
