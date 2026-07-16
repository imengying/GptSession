import type { ArchiveEntry } from "./types";

const textEncoder = new TextEncoder();

interface BinaryArchiveEntry {
  fileName: string;
  bytes: Uint8Array;
}

export interface ZipOptions {
  modifiedAt?: Date;
}

function buildCrc32Table(): Uint32Array {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1)
        ? (0xedb88320 ^ (value >>> 1))
        : (value >>> 1);
    }
    table[index] = value >>> 0;
  }
  return table;
}

const CRC32_TABLE = buildCrc32Table();

function computeCrc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function normalizeFileName(fileName: string): string {
  return String(fileName || "file.json")
    .replaceAll("\\", "/")
    .replace(/^\/+/, "")
    .split("/")
    .filter(Boolean)
    .join("/") || "file.json";
}

function getUniqueEntries(entries: ArchiveEntry[]): BinaryArchiveEntry[] {
  const counts = new Map<string, number>();
  return entries.map((entry, index) => {
    const rawName = normalizeFileName(
      entry.fileName || "file-" + (index + 1) + ".json",
    );
    const count = counts.get(rawName) ?? 0;
    counts.set(rawName, count + 1);
    if (!count) {
      return {
        fileName: rawName,
        bytes: textEncoder.encode(String(entry.text ?? "")),
      };
    }

    const dotIndex = rawName.lastIndexOf(".");
    const hasExtension = dotIndex > 0;
    const baseName = hasExtension ? rawName.slice(0, dotIndex) : rawName;
    const extension = hasExtension ? rawName.slice(dotIndex) : "";
    return {
      fileName: baseName + "-" + (count + 1) + extension,
      bytes: textEncoder.encode(String(entry.text ?? "")),
    };
  });
}

function getDosDateTimeParts(date: Date): { time: number; date: number } {
  const safeDate = Number.isNaN(date.getTime()) ? new Date() : date;
  const year = Math.min(Math.max(safeDate.getFullYear(), 1980), 2107);
  const month = safeDate.getMonth() + 1;
  const day = safeDate.getDate();
  const hours = safeDate.getHours();
  const minutes = safeDate.getMinutes();
  const seconds = Math.floor(safeDate.getSeconds() / 2);
  return {
    time: (hours << 11) | (minutes << 5) | seconds,
    date: ((year - 1980) << 9) | (month << 5) | day,
  };
}

function writeUint16(view: DataView, offset: number, value: number): void {
  view.setUint16(offset, value & 0xffff, true);
}

function writeUint32(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value >>> 0, true);
}

export function buildZipArchive(
  entries: ArchiveEntry[],
  options: ZipOptions = {},
): Blob {
  const normalizedEntries = getUniqueEntries(entries);
  if (!normalizedEntries.length) {
    throw new Error("ZIP 中没有可写入的文件");
  }
  if (normalizedEntries.length > 0xffff) {
    throw new Error("ZIP 文件数量超过当前实现上限");
  }

  const dosDateTime = getDosDateTimeParts(options.modifiedAt ?? new Date());
  const localFiles: Uint8Array[] = [];
  const centralDirectory: Uint8Array[] = [];
  let offset = 0;
  let centralDirectorySize = 0;

  for (const entry of normalizedEntries) {
    const fileNameBytes = textEncoder.encode(entry.fileName);
    const fileData = entry.bytes;
    const crc32 = computeCrc32(fileData);
    const localHeader = new Uint8Array(30 + fileNameBytes.length);
    const localView = new DataView(localHeader.buffer);

    writeUint32(localView, 0, 0x04034b50);
    writeUint16(localView, 4, 20);
    writeUint16(localView, 6, 0x0800);
    writeUint16(localView, 8, 0);
    writeUint16(localView, 10, dosDateTime.time);
    writeUint16(localView, 12, dosDateTime.date);
    writeUint32(localView, 14, crc32);
    writeUint32(localView, 18, fileData.length);
    writeUint32(localView, 22, fileData.length);
    writeUint16(localView, 26, fileNameBytes.length);
    writeUint16(localView, 28, 0);
    localHeader.set(fileNameBytes, 30);
    localFiles.push(localHeader, fileData);

    const centralHeader = new Uint8Array(46 + fileNameBytes.length);
    const centralView = new DataView(centralHeader.buffer);
    writeUint32(centralView, 0, 0x02014b50);
    writeUint16(centralView, 4, 20);
    writeUint16(centralView, 6, 20);
    writeUint16(centralView, 8, 0x0800);
    writeUint16(centralView, 10, 0);
    writeUint16(centralView, 12, dosDateTime.time);
    writeUint16(centralView, 14, dosDateTime.date);
    writeUint32(centralView, 16, crc32);
    writeUint32(centralView, 20, fileData.length);
    writeUint32(centralView, 24, fileData.length);
    writeUint16(centralView, 28, fileNameBytes.length);
    writeUint16(centralView, 30, 0);
    writeUint16(centralView, 32, 0);
    writeUint16(centralView, 34, 0);
    writeUint16(centralView, 36, 0);
    writeUint32(centralView, 38, 0);
    writeUint32(centralView, 42, offset);
    centralHeader.set(fileNameBytes, 46);
    centralDirectory.push(centralHeader);
    centralDirectorySize += centralHeader.length;
    offset += localHeader.length + fileData.length;
  }

  const endOfCentralDirectory = new Uint8Array(22);
  const endView = new DataView(endOfCentralDirectory.buffer);
  writeUint32(endView, 0, 0x06054b50);
  writeUint16(endView, 4, 0);
  writeUint16(endView, 6, 0);
  writeUint16(endView, 8, normalizedEntries.length);
  writeUint16(endView, 10, normalizedEntries.length);
  writeUint32(endView, 12, centralDirectorySize);
  writeUint32(endView, 16, offset);
  writeUint16(endView, 20, 0);

  return new Blob(
    [...localFiles, ...centralDirectory, endOfCentralDirectory] as BlobPart[],
    { type: "application/zip" },
  );
}
