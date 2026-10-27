"""Extra real CTF challenges (public archives with documented flags).

`EXTRA` runs with `real_challenges.py --extra`. `GAPS` lists challenges that
need techniques StegSuite doesn't have yet: they are the backlog
(`real_challenges.py --gaps`), not a pass/fail gate.

Flags come from the official challenge repos (challenge.yaml / flag.txt) or
the linked write-ups. Several were also decoded from the file during
selection (2026-10-20).
"""

P19 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics"
P21 = "https://raw.githubusercontent.com/HHousen/PicoCTF-2021/master/Forensics"
P25A = "https://raw.githubusercontent.com/asatpathy314/picoctf-2025/main/forensics"
P25B = "https://raw.githubusercontent.com/slashben/hadassah-picoctf-2025-writeups/main/writeups/Forensics"
DU23 = "https://raw.githubusercontent.com/DownUnderCTF/Challenges_2023_Public/main"
DU24 = "https://raw.githubusercontent.com/DownUnderCTF/Challenges_2024_Public/main"
IC23 = "https://raw.githubusercontent.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/main/Forensics"
IC24 = "https://raw.githubusercontent.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges/main/Forensics"
TJ23 = "https://raw.githubusercontent.com/TJCSec/tjctf-2023-challenges/main/forensics"
TJ24 = "https://raw.githubusercontent.com/TJCSec/tjctf-2024-challenges/main/forensics"
LA = "https://raw.githubusercontent.com/uclaacm/lactf-archive/main"
UI23 = "https://raw.githubusercontent.com/sigpwny/UIUCTF-2023-Public/main/challenges"

# (local file name, direct url, expected flag)
EXTRA = [
    # picoCTF 2019 WhitePages: em-space=0 / space=1
    ("whitepages.txt", f"{P19}/WhitePages/whitepages.txt",
     "picoCTF{not_all_spaces_are_created_equal_f71be4d2457dc2d068e8b1e7a51ed39a}"),
    # picoCTF 2019 shark on wire 1: one char per UDP packet
    ("sow1.pcap", f"{P19}/shark on wire 1/capture.pcap", "picoCTF{StaT31355_636f6e6e}"),
    # picoCTF 2021 Wireshark doo dooo do doo...: ROT13 flag in an HTTP body
    ("shark1.pcapng", f"{P21}/Wireshark doo dooo do doo.../shark1.pcapng",
     "picoCTF{p33kab00_1_s33_u_deadbeef}"),
    # picoCTF 2021 Wireshark twoo twooo two twoo...: DNS exfil + many decoy flags
    ("shark2.pcapng", f"{P21}/Wireshark twoo twooo two twoo.../shark2.pcapng",
     "picoCTF{dns_3xf1l_ftw_deadbeef}"),
    # picoCTF 2025 RED: RGBA LSB -> repeated base64
    ("red.png", f"{P25A}/RED/red.png", "picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}"),
    # picoCTF 2025 flags are stepic: stepic stego in a 150 MP image
    ("upz.png", f"{P25A}/flags-are-stepic/upz.png", "picoCTF{fl4g_h45_fl4g6f5548ea}"),
    # picoCTF 2025 ph4nt0m 1ntrud3r: base64 fragments in TCP payloads, by timestamp
    ("ph4nt0m.pcap", f"{P25A}/ph4nt0m-1ntrud3r/myNetworkTraffic.pcap",
     "picoCTF{1t_w4snt_th4t_34sy_tbh_4r_959f50d3}"),
    # picoCTF 2025 Event-Viewing: flag in 3 base64 parts across .evtx events
    ("Windows_Logs.evtx", f"{P25B}/Event-Viewing/Windows_Logs.evtx",
     "picoCTF{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}"),
    # picoCTF 2022 Enhance!: flag split across SVG <tspan>s
    ("drawing.flag.svg", f"{P25B}/Enhance!/img/drawing.flag.svg", "picoCTF{3nh4nc3d_aab729dd}"),
    # ImaginaryCTF 2024 bom: UTF-16BE BOM, ASCII flag after FE FF
    ("bom.txt", f"{IC24}/bom/chal.txt", "ictf{th4t_isn7_chin3se}"),
    # TJCTF 2023 neofeudalism: LSB red, msb, column order (zsteg b1,r,msb,yx)
    ("neofeudalism.png", f"{TJ23}/neofeudalism/image.png", "tjctf{feudalism_still_bad_ea31e43b}"),
    # TJCTF 2023 nothing-to-see: zip after the PNG, password in EXIF Title
    ("nothing.png", f"{TJ23}/nothing-to-see/nothing.png", "tjctf{the_end_is_not_the_end_4c261b91}"),
    # TJCTF 2024 conversations: HTTP export -> JPEG EXIF
    ("conversations.pcap", f"{TJ24}/conversations/capture.pcap", "tjctf{I_bh0p_to_sk00l_1337}"),
    # LA CTF 2025 extended: every byte OR 0x80
    ("extended.txt", f"{LA}/2025/misc/extended/chall.txt",
     "lactf{Funnily_Enough_This_Looks_Different_On_Mac_And_Windows}"),
]

EXTRA += [
    # picoCTF 2019 shark on wire 2: text in UDP source ports (5000 + ASCII)
    ("sow2.pcap", f"{P19}/shark on wire 2/capture.pcap", "picoCTF{p1LLf3r3d_data_v1a_st3g0}"),
    # picoCTF 2019 Investigative Reversing 2: flag bits in the raw-byte LSB at
    # offset 2000, LSB-first, +5 per char -> lsb-bits
    ("encoded.bmp", f"{P19}/Investigative Reversing 2/encoded.bmp",
     "picoCTF{n3xt_0n300000000000000000000000006c732cee}"),
    # picoCTF 2021 Disk, disk, sleuth!: ext4 image, flag in a file -> sleuthkit
    ("dds1-alpine.flag.img.gz", f"{P21}/Disk, disk, sleuth!/dds1-alpine.flag.img.gz",
     "picoCTF{f0r3ns1c4t0r_n30phyt3_a011c142}"),
    # Disk, disk, sleuth! II: partitioned ext4; flag drawn in ASCII-art boxes,
    # read by `decode` (boxed chars) after `disk` extracts the file
    ("dds2-alpine.flag.img.gz", f"{P21}/Disk, disk, sleuth! II/dds2-alpine.flag.img.gz",
     "picoCTF{f0r3ns1c4t0r_n0v1c3_0ba8d02d}"),
    # picoCTF 2022 Operation Orchid: disk -> flag.txt.enc + .ash_history password
    # (artifact only on picoCTF's CDN; use the web.archive.org mirror)
    ("orchid.img.gz",
     "https://web.archive.org/web/20220321025118id_/https://artifacts.picoctf.net/c/236/disk.flag.img.gz",
     "picoCTF{h4un71ng_p457_0a710765}"),
    # DUCTF 2024 Bad Policies: GPP cpassword in Groups.xml (published AES key)
    ("badpolicies.zip", f"{DU24}/forensics/badpolicies/publish/badpolicies.zip",
     "DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}"),
    # TJCTF 2024 pals: palette entries with the same colour hide the text
    ("pals.png", f"{TJ24}/pals/pals.png", "tjctf{not_very_palatable_9623c1c9}"),
    # ImaginaryCTF 2024 packed: Packet Tracer .pkz (zip) with the flag in an image (OCR)
    ("routed.pkz", f"{IC24}/packed/routed.pkz", "ictf{ab4697882634d4aeb6f21141ea2724d0}"),
    # TJCTF 2023 miniscule: IDAT is zstd (not zlib) -> png-idat rebuilds the PNG
    ("miniscule.png", f"{TJ23}/miniscule/miniscule.png", "tjctf{zlib_compression_bad_9c8b342}"),
    # ImaginaryCTF 2023 blurry: heavily blurred QR -> qr deblur/upscale
    ("blurry.png", f"{IC23}/blurry/challenge/chall.png", "ictf{blurR1ng_is_n0_m4tch_4_u_2ab140c2}"),
]

# Known gaps: techniques not implemented yet (backlog, see tasks/plan-refactor.md)
GAPS = [
    ("c0rrupt.bin", f"{P19}/c0rrupt/mystery", "picoCTF{c0rrupt10n_1847995}"),             # PNG repair + OCR
    ("1000.tar", f"{P19}/like1000/1000.tar", "picoCTF{l0t5_0f_TAR5}"),                   # deep tar + OCR
    ("m00nwalk.wav", f"{P19}/m00nwalk/message.wav", "picoCTF{beep_boop_im_in_space}"),   # SSTV + OCR
    ("pasta.png", f"{P19}/pastaAAA/ctf.png", "picoCTF{pa$ta_1s_lyf3}"),                  # bit plane + OCR
    ("ir0.png", f"{P19}/Investigative Reversing 0/mystery.png", "picoCTF{f0und_1t_5266a857}"),  # shifted trailer
    ("b1g_mac.zip", f"{P19}/B1g_Mac/b1g_mac.zip", "picoCTF{M4cTim35!}"),                 # zip timestamps
    ("tunn3l_v1s10n", f"{P21}/tunn3l v1s10n/tunn3l_v1s10n", "picoCTF{qu1t3_a_v13w_2020}"),  # BMP repair + OCR
    ("endianness.bin", f"{P25B}/endianness-v2/challengefile",
     "picoCTF{cert!f1Ed_iNd!4n_s0rrY_3nDian_76e05f49}"),                                # word-swapped JPEG
    ("samiam.zip", f"{DU24}/forensics/samiam/publish/samiam.zip", "DUCTF{!checkerboard1}"),  # SAM hive + crack
    ("recipe.txt", f"{DU24}/misc/wackyrecipe/publish/recipe.txt", "DUCTF{2tsp_Vegemite}"),   # Chef esolang
    ("all-fathers-wisdom", f"{DU23}/beginner/all-fathers-wisdom/publish/the-all-fathers-wisdom",
     "DUCTF{Od1n_1S-N0t_C}"),                                                           # rev (XOR array)
    ("blinkybill.wav", f"{DU23}/beginner/blinky-bill/publish/blinkybill.wav",
     "DUCTF{BRINGBACKTHETREES}"),                                                       # morse over music
    ("robot.wav", f"{TJ23}/beep-boop-robot/robot.wav", "tjctf{thisisallonewordlmao}"),   # morse, bare text
    ("out.qoi", f"{TJ24}/purified/out.qoi", "tjctf{r1bbit_ribb1t_69bb0e1d}"),            # QOI recursion
    ("ictf23_forensics.zip", f"{IC23}/forensics/forensics.zip",
     "ictf{n0_corruption_can_stop_u_1b53d8c4}"),                                        # pcap repair
    ("ictf23_web.zip", f"{IC23}/web/challenge/web.zip",
     "ictf{behold_th3_forensics_g4untlet_827b3f13}"),                                   # Firefox profile
    ("sleepy.mp3", f"{IC24}/Sleepy Alarm/togive/morning_n_breakfast.mp3",
     "ictf{1_sl33py_NaYuKi_alarm_2a634dc1bb2}"),                                        # ASK demod
    ("elves.bmp", f"{IC24}/elf in front of a sunset/togive/elves.bmp",
     "ictf{elf_waifus_best_waifus_2h12lntka}"),                                         # BMP height + ELF
    ("EBE.pcap", f"{LA}/2023/misc/ebe/EBE.pcap",
     "lactf{3V1L_817_3xf1l7R4710N_4_7H3_W1N_51D43c8000034d0c}"),                        # evil-bit filter
    ("warning.wav", f"{UI23}/misc/tornado_warning/warning.wav",
     "uiuctf{3rd_w0rst_tor_outbre@k_ev3r}"),                                            # SAME x3 with deliberate errors (raw demod)
]

# Candidates harvested on 2026-10-27 from public challenge repos (file + official
# flag from flag.txt / challenge.yaml / metadata.yaml / README, read via the
# GitHub API). NOT run yet: `real_challenges.py --candidates --only-new`, then
# move each case to EXTRA (solved) or GAPS (with the missing technique).
# HackTheBox repos (cyber-apocalypse-2024/2025, business-ctf-2024) only hold
# write-ups, not the handouts; DUCTF 2025 beepbeep.wav is a Git LFS pointer.
TJ25 = "https://raw.githubusercontent.com/TJCSec/tjctf-2025-challenges/main"
IC25 = "https://raw.githubusercontent.com/ImaginaryCTF/ImaginaryCTF-2025-Challenges/main"
BK24 = "https://raw.githubusercontent.com/cscosu/buckeyectf-2024-public/master"
BK23 = "https://raw.githubusercontent.com/cscosu/buckeyectf-2023-public/master"
DU22 = "https://raw.githubusercontent.com/DownUnderCTF/Challenges_2022_Public/main"
DU25 = "https://raw.githubusercontent.com/DownUnderCTF/Challenges_2025_Public/main"
UT24 = "https://raw.githubusercontent.com/utisss/UTCTF-24/main"
CANDIDATES = [
    # --- TJCTF 2025 (flag: flag.txt / challenge.yaml)
    ("tj25-albumcover.png", f"{TJ25}/forensics/album-cover/albumcover.png", "tjctf{THIS-EASTER-EGG-IS-PRETTY-COOL}"),  # audio -> image (enc.py)
    ("tj25-deep-layers.png", f"{TJ25}/forensics/deep-layers/chall.png", "tjctf{p0lygl0t_r3bb1t_h0l3}"),  # polyglot
    ("tj25-footprint.DS_Store", f"{TJ25}/forensics/footprint/files/.DS_Store", "tjctf{ds_store_is_useful?}"),  # .DS_Store
    ("tj25-suspicious.png", f"{TJ25}/forensics/hidden-message/suspicious.png", "tjctf{steganography_is_fun}"),  # stego
    ("tj25-packet-palette.pcapng", f"{TJ25}/forensics/packet-palette/chall.pcapng", "tjctf{usb1p_f13g_1ns1d3_3_pr0t0c0l}"),  # USB/IP
    ("tj25-quant-lost.jpg", f"{TJ25}/forensics/quant/lost.jpg", "tjctf{th3_Li0n_d0esNt_qUanT1ze}"),  # handout incerto (lost.jpg vs thelion.jpg)
    ("tj25-pietty-runme.png", f"{TJ25}/forensics/thats-pietty-cool/chall/runme.png", "tjctf{p1et_pr1nt3r}"),  # Piet
    ("tj25-masked-qrcode.png", f"{TJ25}/misc/masked/qrcode.png", "tjctf{n0tc4tchingc0vid}"),  # QR mascherato
    # --- ImaginaryCTF 2025 (flag: metadata.yaml / README)
    ("ic25-dinosaur-mosaic.png", f"{IC25}/Forensics/dinosaur/challenge/reconstructed_mosaic.png", "ictf{get_baited_its_actually_an_ankylosaurus}"),  # handout incerto (mosaic vs qr_code.bmp)
    ("ic25-nightcore.mp3", f"{IC25}/Forensics/nightcore/challenge/nightcore.mp3", "ictf{12345678}"),  # ENF (frequenza di rete): probabile gap
    ("ic25-obfuscated-Users.zip", f"{IC25}/Forensics/obfuscated-1/dist/Users.zip", "ictf{Slay4U!!}"),  # profilo Windows
    ("ic25-thrift-capture.pcap", f"{IC25}/Forensics/thrift-store/dist/capture.pcap", "ictf{l1k3_gRPC_bUt_l3ss_g0ogly}"),  # Apache Thrift
    ("ic25-wave.wav", f"{IC25}/Forensics/wave/dist/wave.wav", "ictf{obligatory_metadata_challenge}"),  # metadati
    ("ic25-x-tension.pcapng", f"{IC25}/Forensics/x-tension/dist/chal.pcapng", "ictf{extensions_might_just_suck}"),  # 29 MB
    # --- BuckeyeCTF 2024 / 2023 (flag: challenge.yaml / README)
    ("bk24-couch_potato.wav", f"{BK24}/forensics/couch_potato/dump1.wav", "bctf{1_11k3_5p4m_w17h_my_h4m}"),  # 22 MB, probabile SSTV
    ("bk24-duck-pics.pcapng", f"{BK24}/forensics/duck-pics/capture.pcapng", "bctf{St0p_s3nd1Ng_m3_DuCK_p1c$}"),  # handout incerto (capture vs whole-capture)
    ("bk24-hall-effect.pcapng", f"{BK24}/forensics/hall-effect/capture.pcapng", "bctf{Wh0s3_g0NNa_CarRY_Th3B0atS}"),
    ("bk24-the_cia.pdf", f"{BK24}/forensics/the_cia/protected-cia-document.pdf", "bctf{U_c4N_d0_TH1s_On_w0rd_docs_T0O}"),  # PDF protetto
    ("bk24-unknown.zip", f"{BK24}/forensics/unknown/unknown.zip", "bctf{f1l3_3x73n510n5_4r3_n07_r34l}"),
    ("bk24-wreck-dump", f"{BK24}/forensics/wreck/dump", "bctf{D4MN_7h47_c0r3_dvmp_907_4_GY477}"),  # core dump 38 MB
    ("bk23-replace-me-boot.img", f"{BK23}/forensics-replace-me/boot.img", "bctf{gr33n_r0b0t_ph0N3}"),  # Android boot.img
    ("bk23-wifi-frames.pcap", f"{BK23}/misc-needle-in-the-wifi-stack/dist/frames.pcap", "bctf{tw0_po1nt_4_g33_c0ng3s7i0n}"),  # 802.11
    ("bk23-weather.wav", f"{BK23}/misc-weather/dist/weather.wav", "bctf{0mg_i_10v3_FSK_i75_my_f4v0ri73_m0du147i0n}"),  # FSK
    # --- DownUnderCTF 2022 / 2025 (flag: challenge.yaml)
    ("du22-doxme", f"{DU22}/dfir/doxme/publish/doxme", "DUCTF{WOrd_D0Cs_Ar3_R34L1Y_W3ird}"),  # docx senza estensione
    ("du22-mate.aussie", f"{DU22}/misc/land_down_under/publish/mate.aussie", "DUCTF{ƐƖSSn∀_ɹ_n_sƖɥʇ_D∀Ɛɹ_NㄣƆ_∩0⅄_ℲI}"),  # esolang, flag capovolta
    ("du22-rage.wav", f"{DU22}/misc/rage/publish/rage.wav", "DUCTF{RAGINGTOWEIRDLIBIDO}"),
    ("du25-fishy-capture.pcapng", f"{DU25}/misc/fishy_website/publish/capture.pcapng", "DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}"),  # TLS da decifrare
    ("du25-scrapbooking-warped.png", f"{DU25}/misc/scrapbooking/publish/warped.png", "DUCTF{kn1tting_with_pngs}"),
    ("du25-yo-dawg.zip", f"{DU25}/misc/yodawg/publish/yo-dawg.zip", "DUCTF{1995_to_2025}"),
    # --- UTCTF 2024 (flag: README)
    ("ut24-GitWebsite.tar.gz", f"{UT24}/forensics-git/GitWebsite.tar.gz", "utflag{gitR3fl0g}"),  # git reflog
    ("ut24-keyboard.pcapng", f"{UT24}/forensics-keyboard/keyboard.pcapng", "utflag{learning_stenography_on_a_qwerty_keyboard_is_quite_difficult}"),  # USB keyboard
    ("ut24-contract.pdf", f"{UT24}/forensics-wizardry/contract.pdf", "utflag{s1mple_w1z4rding_mist4k3s}"),
]
