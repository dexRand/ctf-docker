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
    ("m00nwalk.wav", f"{P19}/m00nwalk/message.wav", "picoCTF{beep_boop_im_in_space}"),   # SSTV ok (clock fit + tilt, 11/11): the picture shows only CTF{...} (pico cropped by the sender) + handwritten _ read as -/.: needs CTF flag_format completion
    ("pasta.png", f"{P19}/pastaAAA/ctf.png", "picoCTF{pa$ta_1s_lyf3}"),                  # bit plane + OCR
    ("ir0.png", f"{P19}/Investigative Reversing 0/mystery.png", "picoCTF{f0und_1t_5266a857}"),  # shifted trailer
    ("b1g_mac.zip", f"{P19}/B1g_Mac/b1g_mac.zip", "picoCTF{M4cTim35!}"),                 # zip timestamps
    ("samiam.zip", f"{DU24}/forensics/samiam/publish/samiam.zip", "DUCTF{!checkerboard1}"),  # SAM hive + crack
    ("all-fathers-wisdom", f"{DU23}/beginner/all-fathers-wisdom/publish/the-all-fathers-wisdom",
     "DUCTF{Od1n_1S-N0t_C}"),                                                           # rev (XOR array)
    ("blinkybill.wav", f"{DU23}/beginner/blinky-bill/publish/blinkybill.wav",
     "DUCTF{BRINGBACKTHETREES}"),                                                       # morse over music
    ("robot.wav", f"{TJ23}/beep-boop-robot/robot.wav", "tjctf{thisisallonewordlmao}"),   # morse, bare text
    ("out.qoi", f"{TJ24}/purified/out.qoi", "tjctf{r1bbit_ribb1t_69bb0e1d}"),            # QOI recursion
    ("ictf23_web.zip", f"{IC23}/web/challenge/web.zip",
     "ictf{behold_th3_forensics_g4untlet_827b3f13}"),                                   # Firefox profile
    ("sleepy.mp3", f"{IC24}/Sleepy Alarm/togive/morning_n_breakfast.mp3",
     "ictf{1_sl33py_NaYuKi_alarm_2a634dc1bb2}"),                                        # ASK demod
    ("elves.bmp", f"{IC24}/elf in front of a sunset/togive/elves.bmp",
     "ictf{elf_waifus_best_waifus_2h12lntka}"),                                         # BMP height + ELF
    ("warning.wav", f"{UI23}/misc/tornado_warning/warning.wav",
     "uiuctf{3rd_w0rst_tor_outbre@k_ev3r}"),                                            # SAME x3 with deliberate errors (raw demod)
]

# 02/11: solved by the new analyzers / fixes (ds-store, android-boot + OCR,
# URL-parameter exfil, Wi-Fi SSIDs, decoded hints) and new public challenges
EXTRA += [
    ('tj25-footprint.DS_Store', 'https://raw.githubusercontent.com/TJCSec/tjctf-2025-challenges/main/forensics/footprint/files/.DS_Store',
     'tjctf{ds_store_is_useful?}'),
    ('bk23-replace-me-boot.img', 'https://raw.githubusercontent.com/cscosu/buckeyectf-2023-public/master/forensics-replace-me/boot.img',
     'bctf{gr33n_r0b0t_ph0N3}'),
    ('ic25-x-tension.pcapng', 'https://raw.githubusercontent.com/ImaginaryCTF/ImaginaryCTF-2025-Challenges/main/Forensics/x-tension/dist/chal.pcapng',
     'ictf{extensions_might_just_suck}'),
    ('bk23-wifi-frames.pcap', 'https://raw.githubusercontent.com/cscosu/buckeyectf-2023-public/master/misc-needle-in-the-wifi-stack/dist/frames.pcap',
     'bctf{tw0_po1nt_4_g33_c0ng3s7i0n}'),
    ('tj25-deep-layers.png', 'https://raw.githubusercontent.com/TJCSec/tjctf-2025-challenges/main/forensics/deep-layers/chall.png',
     'tjctf{p0lygl0t_r3bb1t_h0l3}'),
    ('du21-retro-og.jpg', 'https://raw.githubusercontent.com/DownUnderCTF/Challenges_2021_Public/main/forensics/retro/challenge/og.jpg',
     'DUCTF{sicc_paint_skillz!}'),
    ('tj22-fake-geoguessr-lake.jpg', 'https://raw.githubusercontent.com/TJCSec/tjctf-2022-challenges/master/forensics/fake-geoguessr/lake.jpg',
     'tjctf{thats_a_lot_of_metadata}'),
    ('bk25-professors.docx', 'https://raw.githubusercontent.com/cscosu/buckeyectf-2025-public/master/beginner/the_professors_files/OSU_Ethics_Report.docx',
     'bctf{docx_is_zip}'),
    ('wani23-just.mp4', 'https://raw.githubusercontent.com/wani-hackase/wanictf2023-writeup/main/for/Just_mp4/file/chall.mp4',
     'FLAG{H4v1n_fun_1nn1t}'),
    ('wani23-lowkey.pcap', 'https://raw.githubusercontent.com/wani-hackase/wanictf2023-writeup/main/for/lowkey_messedup/file/chall.pcap',
     'FLAG{Big_br0ther_is_watching_y0ur_keyb0ard}'),
    ('wani24-tiny_usb.iso', 'https://raw.githubusercontent.com/wani-hackase/wanictf2024-writeup/main/for/tiny_usb/file/chal_tiny_usb.iso',
     'FLAG{hey_i_just_bought_a_usb}'),
]

# 02/11 harvest: not solved yet (missing technique in the comment)
GAPS += [
    ('tj22-cool-school.png', 'https://raw.githubusercontent.com/TJCSec/tjctf-2022-challenges/master/forensics/cool-school/image.png',
     'tjctf{l0l_st3g_s0_co0l}'),  # stego immagine non coperta (da investigare)
    ('tj22-fried-clams', 'https://raw.githubusercontent.com/TJCSec/tjctf-2022-challenges/master/misc/fried-clams/bin/chall',
     'tjctf{noooo_not_clam_b64b833796b08d47}'),  # formato non riconosciuto (da investigare)
    ('tj22-spongebob.png', 'https://raw.githubusercontent.com/TJCSec/tjctf-2022-challenges/master/forensics/spongebob/image.png',
     'tjctf{such_pogg3rs_ctf}'),  # altezza IHDR corretta da png-repair; flag piccola bianca con contorno: OCR non la legge
    ('ui21-megacorp-01.cap', 'https://raw.githubusercontent.com/sigpwny/UIUCTF-2021-Public/master/misc/CEO/megacorp-01.cap',
     'uiuctf{nanotechnology}'),  # WPA: hcxpcapngtool estrae 2 hash 22000 (SSID joesheer) e hashcat li cracca con un dizionario ad hoc ('nanotechnology', verificato); non e' nelle wordlist piccole (<1 MB) e a ~125 H/s rockyou non e' praticabile; il flag va avvolto a mano (#11)
    ('tamu24-smp.log', 'https://raw.githubusercontent.com/tamuctf/tamuctf-2024/master/forensics/smp/smp.log',
     'gigem{w3_l0v3_pl1y1n_mc_smp}'),  # log Minecraft: blocchi da tracciare in 3D e leggere a occhio
    ('uoft24-illusion.pcapng', 'https://raw.githubusercontent.com/UofTCTF/uoftctf-2024-chals-public/master/Forensics/Illusion/traffic.pcapng',
     'uoftctf{Tr3V0r_C2_1s_H4rd_T0_D3t3c7}'),  # C2 TrevorC2: decifratura AES con la chiave di default
    ('tamu23-discordance.zip', 'https://raw.githubusercontent.com/tamuctf/tamuctf-2023/master/forensics/discordance/package.zip',
     'gigem{d15c0rd_k3ep5_d3l37ed_f1l3s?!?!}'),  # pacchetto dati Discord: file cancellati referenziati nei messaggi
    ('wani23-apocalypse.png', 'https://raw.githubusercontent.com/wani-hackase/wanictf2023-writeup/main/for/Apocalypse/file/chall.png',
     'FLAG{Watch_out_4_2023_21036}'),  # aCropalypse (CVE-2023-21036): dati dopo IEND da ricostruire
    ('wani23-peg.pcapng', 'https://raw.githubusercontent.com/wani-hackase/wanictf2023-writeup/main/for/beg_for_a_peg/file/log.pcapng',
     'FLAG{Hug_a_pug_less_than_three}'),  # JPEG ricostruito dallo stream TCP (porta 4500) ma testo stilizzato: OCR non esatto
    ('wani24-streamer.pcap', 'https://raw.githubusercontent.com/wani-hackase/wanictf2024-writeup/main/for/I_wanna_be_a_streamer/file/file.pcap',
     'FLAG{Th4nk_y0u_f0r_W4tching}'),  # video in RTP/RTSP da ricostruire (#11)
    ('tcp1p23-compromised.pcap', 'https://raw.githubusercontent.com/TCP1P/TCP1P-CTF-2023-Challenges/main/Forensic/Compromised/dist/compromised.pcap',
     'TCP1P{3xpl0171n6_pr3d1c74bl3__p1d_533d_f0r_7h3_w1n_98ef246706}'),  # FTPS da decifrare con la chiave privata
    ('tcp1p23-reminiscence.pcap', 'https://raw.githubusercontent.com/TCP1P/TCP1P-CTF-2023-Challenges/main/Forensic/Reminiscence/dist/reminiscence.pcap',
     'TCP1P{r3min1scing_s0meth1ng_b4ck_in_th3_0ld_days_a01fef0086}'),  # SSH (OpenSSH 4.3, DH group1): decifratura con chiavi deboli, non generica
    ('tcp1p23-ez.pdf', 'https://raw.githubusercontent.com/TCP1P/TCP1P-CTF-2023-Challenges/main/Forensic/Ez%20PDF/TCP1P-CTF.pdf',
     'TCP1P{D01n9_F023n51C5_0N_pdf_f1L35_15_345y_15N7_17_l3jaf9ci293m1d}'),  # PDF (da investigare, #14)
    ('tcp1p23-scrambled-egg.zip', 'https://raw.githubusercontent.com/TCP1P/TCP1P-CTF-2023-Challenges/main/Forensic/scrambled%20egg/dist/scrambled_egg.zip',
     'TCP1P{y0Ur_u5u4L_pN9_cHUnk_ch4LL}'),  # chunk PNG rimescolati con uno schema ad hoc (scramble.py): non generico
    ('cor23-sanitycheck.png', 'https://raw.githubusercontent.com/Crusaders-of-Rust/corCTF-2023-public-challenge-archive/master/misc/sanity-check/sanitycheck.png',
     'corctf{aaaaaaaaaaaaaaaaaaaaaaaa}'),  # WordArt: OCR non legge, e le 'a' disegnate non sono 24 come nella flag ufficiale
]

# 03/11: QR a strisce sui frame GIF, stream NTFS + pezzi numerati, dati sotto
# una entry 'cartella' di uno zip
EXTRA += [
    ('du21-challenge.gif', 'https://raw.githubusercontent.com/DownUnderCTF/Challenges_2021_Public/main/forensics/how-to-pronounce-gif/challenge/challenge.gif',
     'DUCTF{aM_1_haXX0r_n0w?}'),
    ('tcp1p23-hide-split.zip', 'https://raw.githubusercontent.com/TCP1P/TCP1P-CTF-2023-Challenges/main/Forensic/hide%20and%20split/dist/challenge.zip',
     'TCP1P{hidden_flag_in_the_extended_attributes_fea73c5920aa8f1c}'),
    ('tj22-sneaker-zipper.zip', 'https://raw.githubusercontent.com/TJCSec/tjctf-2022-challenges/master/forensics/sneaker-zipper/chall.zip',
     'tjctf{sneakers_with_zippers_are_hip_no?_874d174bb26fcf95}'),
]

# 03/11 pomeriggio: allegati PDF + CryptoJS, OCR su piu' righe, tunnel DNS esadecimale
EXTRA += [
    ('hero5-strange.pdf', 'https://raw.githubusercontent.com/HeroCTF/HeroCTF_v5/main/Steganography/PDF-Mess/strange.pdf',
     'Hero{M4L1C10U5_C0D3_1N_PDF}'),
    ('wani23-updog', 'https://raw.githubusercontent.com/wani-hackase/wanictf2023-writeup/main/for/whats_happening/file/updog',
     'FLAG{n0th1ng_much}'),
    ('du21-notmyname.pcapng.7z', 'https://raw.githubusercontent.com/DownUnderCTF/Challenges_2021_Public/main/forensics/Thats_Not_My_Name/challenge/notmyname.pcapng.7z',
     'DUCTF{c4t_g07_y0ur_n4m3}'),
]

# 04/11: protocollo a pezzi ricomposto (deframe) + OCR testo chiaro su scuro;
# tastiera USB con tasti sovrapposti e Ctrl+Backspace, '$' nel corpo della flag
EXTRA += [
    ('tj25-packet-palette.pcapng', 'https://raw.githubusercontent.com/TJCSec/tjctf-2025-challenges/main/forensics/packet-palette/chall.pcapng',
     'tjctf{usb1p_f13g_1ns1d3_3_pr0t0c0l}'),
]

# Candidates harvested on 2026-10-27 from public challenge repos (file + official
# flag from flag.txt / challenge.yaml / metadata.yaml / README, read via the
# GitHub API). Run with `real_challenges.py --candidates --only-new`, then
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
CANDIDATES: list[tuple[str, str, str]] = []   # smistate il 2026-10-27: 4 risolte (in EXTRA), 28 in GAPS


# --- smistate il 2026-10-27 (ex CANDIDATES, risolte) ---
EXTRA += [
    ("tj25-suspicious.png", f"{TJ25}/forensics/hidden-message/suspicious.png", "tjctf{steganography_is_fun}"),
    ("ic25-wave.wav", f"{IC25}/Forensics/wave/dist/wave.wav", "ictf{obligatory_metadata_challenge}"),
    ("ut24-GitWebsite.tar.gz", f"{UT24}/forensics-git/GitWebsite.tar.gz", "utflag{gitR3fl0g}"),
    ("ut24-contract.pdf", f"{UT24}/forensics-wizardry/contract.pdf", "utflag{s1mple_w1z4rding_mist4k3s}"),
]

# --- candidate 2026-10-27 non risolte: tecnica mancante ---
GAPS += [
    ("tj25-albumcover.png", f"{TJ25}/forensics/album-cover/albumcover.png", "tjctf{THIS-EASTER-EGG-IS-PRETTY-COOL}"),  # payload audio/immagine prodotto da enc.py: non riconosciuto
    ("tj25-pietty-runme.png", f"{TJ25}/forensics/thats-pietty-cool/chall/runme.png", "tjctf{p1et_pr1nt3r}"),  # Piet esolang: serve un interprete
    ("ic25-nightcore.mp3", f"{IC25}/Forensics/nightcore/challenge/nightcore.mp3", "ictf{12345678}"),  # ENF (frequenza di rete) nel rumore: demodulazione dedicata
    ("ic25-obfuscated-Users.zip", f"{IC25}/Forensics/obfuscated-1/dist/Users.zip", "ictf{Slay4U!!}"),  # profilo Windows: winreg legge la hive NTUSER.DAT (2131 chiavi, 4214 valori: Environment, RecentDocs, RunMRU, TypedPaths, UserAssist) ma il flag non e' li'; 455s, 401 nodi (MAX_NODES=400)
    ("ic25-thrift-capture.pcap", f"{IC25}/Forensics/thrift-store/dist/capture.pcap", "ictf{l1k3_gRPC_bUt_l3ss_g0ogly}"),  # protocollo Apache Thrift: serve un decode binario
    ("bk24-couch_potato.wav", f"{BK24}/forensics/couch_potato/dump1.wav", "bctf{1_11k3_5p4m_w17h_my_h4m}"),  # 22 MB: probabile SSTV/spettro su un canale non coperto
    ("bk24-hall-effect.pcapng", f"{BK24}/forensics/hall-effect/capture.pcapng", "bctf{Wh0s3_g0NNa_CarRY_Th3B0atS}"),  # protocollo/dato non emerso: da investigare
    ("bk24-the_cia.pdf", f"{BK24}/forensics/the_cia/protected-cia-document.pdf", "bctf{U_c4N_d0_TH1s_On_w0rd_docs_T0O}"),  # PDF cifrato: pdfcrack+rockyou non lo apre (il lock ora viene segnalato)
    ("bk24-wreck-dump", f"{BK24}/forensics/wreck/dump", "bctf{D4MN_7h47_c0r3_dvmp_907_4_GY477}"),  # core dump 37 MB: il flag non e' in chiaro (analisi heap/GDB)
    ("bk23-weather.wav", f"{BK23}/misc-weather/dist/weather.wav", "bctf{0mg_i_10v3_FSK_i75_my_f4v0ri73_m0du147i0n}"),  # FSK (meteo): demodulatore FSK dedicato
    ("du22-doxme", f"{DU22}/dfir/doxme/publish/doxme", "DUCTF{WOrd_D0Cs_Ar3_R34L1Y_W3ird}"),  # docx senza estensione: la flag e' in due PNG word/media (image1=prefisso, image2=suffisso); serve OCR+join tra nodi, l'office non la ricompone
    ("du22-mate.aussie", f"{DU22}/misc/land_down_under/publish/mate.aussie", "DUCTF{ƐƖSSn∀_ɹ_n_sƖɥʇ_D∀Ɛɹ_NㄣƆ_∩0⅄_ℲI}"),  # esolang 'aussie' con flag capovolta: serve un interprete
    ("du22-rage.wav", f"{DU22}/misc/rage/publish/rage.wav", "DUCTF{RAGINGTOWEIRDLIBIDO}"),  # audio stego non coperto (da investigare)
    ("du25-fishy-capture.pcapng", f"{DU25}/misc/fishy_website/publish/capture.pcapng", "DUCTF{1_gu355_y0u_c4n_d3cRyPT_TLS_tr4ff1c}"),  # TLS da decifrare: la chiave non e' nel pcap
    ("du25-scrapbooking-warped.png", f"{DU25}/misc/scrapbooking/publish/warped.png", "DUCTF{kn1tting_with_pngs}"),  # PNG 'knitting': immagine da ricomporre (righe/colonne mescolate)
    ("du25-yo-dawg.zip", f"{DU25}/misc/yodawg/publish/yo-dawg.zip", "DUCTF{1995_to_2025}"),  # .NET assembly: la flag sta in una risorsa compressa
    ("ut24-keyboard.pcapng", f"{UT24}/forensics-keyboard/keyboard.pcapng", "utflag{learning_stenography_on_a_qwerty_keyboard_is_quite_difficult}"),  # stenografia: ogni report e' un accordo di tasti (layout steno)
]

# --- risolto il 05/11 (task jpeg-dqt, verificato con --gaps)
EXTRA += [
    ("tj25-quant-lost.jpg", f"{TJ25}/forensics/quant/lost.jpg", "tjctf{th3_Li0n_d0esNt_qUanT1ze}"),  # DQT azzerate: ricostruite (all-ones)
]

# --- risolto il 05/11 (tar-chain + variante OCR unleet)
EXTRA += [
    ("1000.tar", "https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics/like1000/1000.tar",
     "picoCTF{l0t5_0f_TAR5}"),  # 999 tar annidati -> flag.png, OCR 2x binarizzato
]

# --- verificati il 06/11 con `real_challenges.py --gaps`: passano, spostati qui
EXTRA += [
    ("c0rrupt.bin", f"{P19}/c0rrupt/mystery", "picoCTF{c0rrupt10n_1847995}"),
    ("tunn3l_v1s10n", f"{P21}/tunn3l v1s10n/tunn3l_v1s10n", "picoCTF{qu1t3_a_v13w_2020}"),
    ("recipe.txt", f"{DU24}/misc/wackyrecipe/publish/recipe.txt", "DUCTF{2tsp_Vegemite}"),
    ("bk24-unknown.zip", f"{BK24}/forensics/unknown/unknown.zip", "bctf{f1l3_3x73n510n5_4r3_n07_r34l}"),
]
EXTRA += [
    ("ictf23_forensics.zip", f"{IC23}/forensics/forensics.zip",
     "ictf{n0_corruption_can_stop_u_1b53d8c4}"),   # pcap repair — verificato 06/11
    ("EBE.pcap", f"{LA}/2023/misc/ebe/EBE.pcap",
     "lactf{3V1L_817_3xf1l7R4710N_4_7H3_W1N_51D43c8000034d0c}"),   # evil bit — verificato 06/11
]
# --- 10/11 (review): un caso usa SOLO il file distribuito dalla challenge
# (README "Distribution"), mai un file della soluzione. duck-pics: `capture.pcapng`
# e' quello distribuito e passa (04/11); `whole-capture` non e' un allegato.
EXTRA += [
    ("bk24-duck-pics.pcapng",
     f"{BK24}/forensics/duck-pics/capture.pcapng",
     "bctf{St0p_s3nd1Ng_m3_DuCK_p1c$}"),
]
GAPS += [
    # dinosaur: si distribuisce solo STEGosaurus.txt (emoji del Discord di ImaginaryCTF
    # da mappare sulle icone -> fotomosaico -> QR). qr_code.bmp e il mosaico sono la soluzione.
    ("ic25-dinosaur-STEGosaurus.txt",
     f"{IC25}/Forensics/dinosaur/dist/STEGosaurus.txt",
     "ictf{get_baited_its_actually_an_ankylosaurus}"),
]

# --- 11/11: byte-swap (32-bit) -> JPEG -> OCR "picoC TF{": known prefix split by a
# space glued back in vision._confusable_variants. PASS 10.2 s (--gaps -k endianness)
EXTRA += [
    ("endianness.bin", f"{P25B}/endianness-v2/challengefile",
     "picoCTF{cert!f1Ed_iNd!4n_s0rrY_3nDian_76e05f49}"),
]

# --- 12/11: QR de-masking (qr.py): i moduli dati XOR-ati con lo XOR delle 8
# maschere standard QR ("all the masks") vengono ripristinati e letti da zbarimg.
EXTRA += [
    ("tj25-masked-qrcode.png", f"{TJ25}/misc/masked/qrcode.png", "tjctf{n0tc4tchingc0vid}"),
]
