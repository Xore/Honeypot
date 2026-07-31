rule AutoGen_Cw6hi673_exe
{
    meta:
        description = "Auto-generated rule for cw6hi673_exe (honeypot telemetry)"
        author      = "honeypot-bot"
        date        = "2026-07-31"
        auto_generated = true
        sample_sha256 = "b8236efcfcdeb61c932b19488d58ba10c2033ca0b9a4bcf95d0dadc8620af196"
        file_types  = "Win32 EXE"
        reference1  = "https://www.virustotal.com/gui/file/b8236efcfcdeb61c932b19488d58ba10c2033ca0b9a4bcf95d0dadc8620af196"
        reference2  = "https://bazaar.abuse.ch/sample/b8236efcfcdeb61c932b19488d58ba10c2033ca0b9a4bcf95d0dadc8620af196/"

    strings:
        $s1 = "let tileErrors=0;const tiles=L.tileLayer(tileURL,{maxZoom:19,noWrap:true,attribution:'<a href=\"https://www.openstreetmap.org/copyright\">'+safeAttribution.innerHTML+'</a>'})" ascii nocase
        $s2 = "A A!A\"A#A$A%A&A'A(A)A*A+A,A-A.A/A0A1A2A3A4A5A6A7A8A9A:A;A<A=A>A?A@AAABACADAEAFAGAHAIAJAKALAMANAOAPAQARASATAUAVAWAXAYAZA[A\\A]A^A_A`AaAbAcAdAeAfAgAhAiAjAkAlAmAnAoApAqArAsAtAuAvAwAxAyAzA{A|A}A~B" ascii nocase
        $s3 = ")(tvrRuUeEaAlLsS01bBoOxX+-nNiIfFpP\\a\\f\\n\\r\\t\\u\\U\"\"53->::\\0\\9\\c\\d\\/\\$\\(\\)\\*\\-\\.\\?\\[\\]\\^\\{\\|\\}iddoinif*/#?\\\"\\'0x[]LlLtLuMnLCPePcCcScPdNdMePfCfPiNlZlSmLmSkPsLoNoPoSoZpCoZsMcCsCnYi])iv--%xTo>" ascii nocase
        $s4 = "<span class=\"gen\">{{if .Chain}}attack chain &bull; {{.IP}}{{else}}event explorer{{end}} &bull; generated {{.Generated.Format \"2006-01-02 15:04:05 MST\"}}</span>" ascii nocase
        $s5 = "if (!tab.querySelector(\"i\")) tab.insertAdjacentHTML(\"afterbegin\", `<i class=\"bi ${tabIcons[tab.dataset.dashboardTab] || \"bi-circle\"} me-2\" aria-hidden=\"true\"></i>`);" ascii nocase
        $s6 = "<header><h1><a href=\"/\">XORE<span>//</span>HONEYPOT</a></h1><span class=\"gen\">executed commands &bull; generated {{.Generated.Format \"2006-01-02 15:04:05 MST\"}}</span></header>" ascii nocase
        $s7 = "on unix&#9;htmlmetacitecolsformhighhreficonkindlanglistloopnamerowssizespanstepwrapcaseelsevoidwith<!--(?:)\\/[](\"'/AVX2elf.int8uintchanfunccallArgsCall != MarkAhomChamKawiLisuMiaoModiNewaThaiToto" ascii nocase
        $s8 = "const map=L.map(container,{minZoom:1,maxZoom:12,maxBounds:[[-85,-180],[85,180]],maxBoundsViscosity:.75,worldCopyJump:false}).setView(savedView.center,savedView.zoom);" ascii nocase
        $s9 = "crypto/internal/fips140/ecdsa.newDRBG[go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }].func1" ascii nocase
        $s10 = "crypto/internal/fips140/tls13.NewEarlySecret[go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }]" ascii nocase
        $s11 = "crypto/internal/fips140/tls13.deriveSecret[go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }]" ascii nocase
        $s12 = "crypto/internal/fips140/tls12.MasterSecret[go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }]" ascii nocase
        $s13 = "crypto/internal/fips140/tls13.NewEarlySecret[go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }].func1" ascii nocase
        $s14 = "internal/saferio.SliceCap[go.shape.struct { Name [8]uint8; Value uint32; SectionNumber int16; Type uint16; StorageClass uint8; NumberOfAuxSymbols uint8 }]" ascii nocase
        $s15 = "sync/atomic.(*Pointer[go.shape.struct { internal/bisect.recent [128][4]uint64; internal/bisect.mu sync.Mutex; internal/bisect.m map[uint64]bool }]).CompareAndSwap" ascii nocase
        $s16 = "sync/atomic.(*Pointer[go.shape.struct { crypto/internal/fips140/drbg.c crypto/internal/fips140/aes.CTR; crypto/internal/fips140/drbg.reseedCounter uint64 }]).Swap" ascii nocase
        $s17 = "*struct { F uintptr; X0 func() go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }; X1 *[3]uintptr }" ascii nocase
        $s18 = "*struct { F uintptr; X0 func() go.shape.interface { BlockSize() int; Reset(); Size() int; Sum([]uint8) []uint8; Write([]uint8) (int, error) }; X1 *[4]uintptr }" ascii nocase
        $s19 = "sync/atomic.(*Pointer[go.shape.struct { os.mu sync.Mutex; os.buf *[]uint8; os.bufp int; os.h syscall.Handle; os.vol uint32; os.class uint32; os.path string }]).CompareAndSwap" ascii nocase
        $s20 = "sEET+00+01CATWATEATGMTHSTHDT-03-04-05ESTCSTCDTMSTMDT-02-01EDTASTADTPSTPDTNSTNDT+03+04+07+06IST+09+08IDT+12PKT+11KST+05JST+10-11-12-08-09+13CETBSTMSK-06+14 m=StdDltnil01_EOF%25\"" ascii nocase

    condition:
        8 of ($s*)
}
