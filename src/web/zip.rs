use std::collections::HashSet;

use js_sys::Date;

use super::model::ArchiveEntry;

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffff_ffff
}

fn normalized_name(value: &str, fallback: &str) -> String {
    let normalized = value
        .replace('\\', "/")
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        fallback.to_owned()
    } else {
        normalized
    }
}

fn unique_entries(entries: &[ArchiveEntry]) -> Vec<(String, Vec<u8>)> {
    let mut used = HashSet::new();
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let fallback = format!("file-{}.json", index + 1);
            let raw = normalized_name(&entry.file_name, &fallback);
            let dot = raw.rfind('.').filter(|position| *position > 0);
            let (base, extension) = dot.map_or_else(
                || (raw.clone(), String::new()),
                |position| (raw[..position].to_owned(), raw[position..].to_owned()),
            );
            let mut name = raw;
            let mut suffix = 2;
            while !used.insert(name.to_lowercase()) {
                name = format!("{base}-{suffix}{extension}");
                suffix += 1;
            }
            (name, entry.text.as_bytes().to_vec())
        })
        .collect()
}

fn dos_date_time(milliseconds: f64) -> (u16, u16) {
    let date = Date::new(&milliseconds.into());
    let year = date.get_full_year().clamp(1980, 2107) as u16;
    let month = (date.get_month() + 1).clamp(1, 12) as u16;
    let day = date.get_date().clamp(1, 31) as u16;
    let hours = date.get_hours().min(23) as u16;
    let minutes = date.get_minutes().min(59) as u16;
    let seconds = (date.get_seconds().min(59) / 2) as u16;
    (
        (hours << 11) | (minutes << 5) | seconds,
        ((year - 1980) << 9) | (month << 5) | day,
    )
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub fn build_zip(entries: &[ArchiveEntry], modified_at_ms: f64) -> Result<Vec<u8>, String> {
    let entries = unique_entries(entries);
    if entries.is_empty() {
        return Err("ZIP 中没有可写入的文件".to_owned());
    }
    if entries.len() > usize::from(u16::MAX) {
        return Err("ZIP 文件数量超过当前实现上限".to_owned());
    }
    let entry_count = u16::try_from(entries.len()).map_err(|_| "ZIP 文件数量超过当前实现上限")?;

    let (dos_time, dos_date) = dos_date_time(modified_at_ms);
    let mut local = Vec::new();
    let mut central = Vec::new();
    let mut offset = 0_u32;

    for (name, data) in entries {
        let name = name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| "ZIP 文件名过长")?;
        let data_len = u32::try_from(data.len()).map_err(|_| "ZIP 文件过大")?;
        let checksum = crc32(&data);

        push_u32(&mut local, 0x0403_4b50);
        push_u16(&mut local, 20);
        push_u16(&mut local, 0x0800);
        push_u16(&mut local, 0);
        push_u16(&mut local, dos_time);
        push_u16(&mut local, dos_date);
        push_u32(&mut local, checksum);
        push_u32(&mut local, data_len);
        push_u32(&mut local, data_len);
        push_u16(&mut local, name_len);
        push_u16(&mut local, 0);
        local.extend_from_slice(name);
        local.extend_from_slice(&data);

        push_u32(&mut central, 0x0201_4b50);
        push_u16(&mut central, 20);
        push_u16(&mut central, 20);
        push_u16(&mut central, 0x0800);
        push_u16(&mut central, 0);
        push_u16(&mut central, dos_time);
        push_u16(&mut central, dos_date);
        push_u32(&mut central, checksum);
        push_u32(&mut central, data_len);
        push_u32(&mut central, data_len);
        push_u16(&mut central, name_len);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name);

        let local_header = 30_u32 + u32::from(name_len);
        offset = offset
            .checked_add(local_header)
            .and_then(|value| value.checked_add(data_len))
            .ok_or_else(|| "ZIP 文件过大".to_owned())?;
    }

    let central_size = u32::try_from(central.len()).map_err(|_| "ZIP 目录过大")?;
    let mut output = local;
    output.extend_from_slice(&central);
    push_u32(&mut output, 0x0605_4b50);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, entry_count);
    push_u16(&mut output, entry_count);
    push_u32(&mut output, central_size);
    push_u32(&mut output, offset);
    push_u16(&mut output, 0);
    Ok(output)
}
