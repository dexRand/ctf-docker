// Human-readable names for tools. Keys are tool names as exposed by the API
// plus the pseudo-origins the UI invents ('upload', 'extracted', 'raw scan').
// Missing keys fall back to the raw name, so a new tool is never blank.
export const TOOL_LABELS = {
  // pseudo-origins
  upload: 'Caricato da te',
  extracted: 'Estratto',
  'raw scan': 'Scansione raw',

  // metadata
  file: 'Tipo file',
  exiftool: 'Metadati EXIF',
  identify: 'Info immagine',
  ffprobe: 'Info audio/video',
  pdfinfo: 'Info PDF',

  // text
  strings: 'Stringhe',
  pdftotext: 'Testo del PDF',
  pdfid: 'Struttura PDF',
  'binwalk-scan': 'Scansione binwalk',
  decode: 'Decodifica annidata',

  // hex
  hexyl: 'Hex colorato',
  xxd: 'Hex dump',
  hexdump: 'Hex dump',

  // extract
  'binwalk-extract': 'Estrazione binwalk',
  foremost: 'Estrazione per firma',
  '7z': 'Estrazione archivi',
  pngcheck: 'Controllo PNG',
  'png-repair': 'Riparazione PNG',
  'image-repair': 'Riparazione JPEG/BMP',

  // network
  pcap: 'Analisi traffico',

  // steg
  qr: 'QR e barcode',
  zsteg: 'Stego LSB',
  steghide: 'Stegohide',
  outguess: 'Outguess',
  jsteg: 'JSteg',
  'png-chunks': 'Chunk PNG',
  openstego: 'OpenStego',
  'bit-planes': 'Piani di bit',
  'channel-remap': 'Rimappatura canali',

  // vision
  'image-enhance': 'Enhancement',
  'gif-frames': 'Frame GIF',
  ocr: 'OCR testo',

  // audio
  spectrogram: 'Spettrogramma',
  waveform: 'Waveform',
  'wav-lsb': 'LSB del WAV',

  // radio
  morse: 'Morse da audio',
  'morse-text': 'Morse da testo',
  dtmf: 'Toni DTMF',
}

export function toolLabel(name) {
  if (!name) return ''
  return TOOL_LABELS[name] || name
}