use account_action_interpreter::{Action, build_elf, encode_actions};
use serde_json::{Value, json};
use std::{env, fs, path::PathBuf, process::ExitCode};

const USAGE: &str = "Usage:\n  account-action-interpreter build [output.so]\n  account-action-interpreter encode actions.json output.bin\n  account-action-interpreter decode-result result.bin";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let command = args.first().and_then(|arg| arg.to_str());
    match command {
        Some("build") if args.len() <= 2 => {
            let output = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts/account_actions.so")
            });
            build_elf(&output)
                .map_err(|error| format!("building {}: {error}", output.display()))?;
            println!("Built {}", output.display());
        }
        Some("encode") if args.len() == 3 => {
            let input = PathBuf::from(&args[1]);
            let output = PathBuf::from(&args[2]);
            let json = fs::read(&input)
                .map_err(|error| format!("reading {}: {error}", input.display()))?;
            let actions: Vec<Action> = serde_json::from_slice(&json)
                .map_err(|error| format!("parsing {}: {error}", input.display()))?;
            let data = encode_actions(&actions)?;
            fs::write(&output, &data)
                .map_err(|error| format!("writing {}: {error}", output.display()))?;
            println!(
                "Encoded {} actions into {} bytes: {}",
                actions.len(),
                data.len(),
                output.display()
            );
        }
        Some("decode-result") if args.len() == 2 => {
            let input = PathBuf::from(&args[1]);
            let data = fs::read(&input)
                .map_err(|error| format!("reading {}: {error}", input.display()))?;
            let result = decode_result(&data)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .map_err(|error| format!("formatting result: {error}"))?
            );
        }
        Some("--help" | "-h") if args.len() == 1 => println!("{USAGE}"),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn decode_result(data: &[u8]) -> Result<Value, String> {
    const HEADER_LEN: usize = 20;
    if data.len() < HEADER_LEN || &data[..4] != b"ACR1" {
        return Err("result must begin with a complete ACR1 header (20 bytes)".into());
    }
    let step = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let opcode = data[8];
    let account = data[9];
    let status = u64::from_le_bytes(data[10..18].try_into().unwrap());
    let payload_len = u16::from_le_bytes(data[18..20].try_into().unwrap()) as usize;
    if data.len() != HEADER_LEN + payload_len {
        return Err(format!(
            "result declares {payload_len} payload bytes but contains {}",
            data.len() - HEADER_LEN
        ));
    }
    let payload = &data[HEADER_LEN..];
    let name = match opcode {
        0 => "read_address",
        1 => "read_lamports",
        2 => "read_data",
        3 => "read_owner",
        4 => "read_executable",
        5 => "write_data",
        6 => "resize_grow",
        7 => "resize_shrink",
        8 => "resize_zero",
        9 => "credit_lamports",
        10 => "debit_lamports",
        11 => "zero_lamports",
        12 => "reassign_owner",
        13 => "mark_executable",
        14 => "remove_executable",
        _ => "unknown",
    };
    let mut result = json!({
        "step": step,
        "opcode": opcode,
        "action": name,
        "account": account,
        "status": status,
        "payload_hex": hex(payload),
    });
    if status == 0 {
        let value = match opcode {
            0 | 3 => {
                require_payload_len(name, payload, 32)?;
                Some(json!(hex(payload)))
            }
            1 => {
                require_payload_len(name, payload, 8)?;
                Some(json!(u64::from_le_bytes(payload.try_into().unwrap())))
            }
            2 => Some(json!(hex(payload))),
            4 => {
                require_payload_len(name, payload, 1)?;
                if payload[0] > 1 {
                    return Err("read_executable payload must be 0 or 1".into());
                }
                Some(json!(payload[0] == 1))
            }
            _ => None,
        };
        if let Some(value) = value {
            result["value"] = value;
        }
    }
    Ok(result)
}

fn require_payload_len(name: &str, payload: &[u8], expected: usize) -> Result<(), String> {
    if payload.len() != expected {
        return Err(format!(
            "{name} requires a {expected}-byte payload, got {}",
            payload.len()
        ));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(opcode: u8, status: u64, payload: &[u8]) -> Vec<u8> {
        let mut data = b"ACR1".to_vec();
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&[opcode, 2]);
        data.extend_from_slice(&status.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn decodes_result_and_rejects_malformed_records() {
        let data = record(1, 0, &u64::MAX.to_le_bytes());
        let decoded = decode_result(&data).unwrap();
        assert_eq!(decoded["step"], 7);
        assert_eq!(decoded["account"], 2);
        assert_eq!(decoded["value"], json!(u64::MAX));
        assert_eq!(decoded["payload_hex"], "ffffffffffffffff");
        assert!(decode_result(&data[..data.len() - 1]).is_err());
        let mut trailing = data;
        trailing.push(0);
        assert!(decode_result(&trailing).is_err());
        assert!(decode_result(&record(4, 0, &[2])).is_err());
        assert!(decode_result(&record(0, 0, &[])).is_err());
        assert_eq!(decode_result(&record(4, 0, &[1])).unwrap()["value"], true);
        // A failed read has no value to decode and may carry an empty payload.
        assert!(
            decode_result(&record(1, 42, &[]))
                .unwrap()
                .get("value")
                .is_none()
        );
    }
}
