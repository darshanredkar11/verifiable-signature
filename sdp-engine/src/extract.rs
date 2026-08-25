use sha2::{Digest, Sha256};

use crate::claim::{Claim, ClaimSchema, ValueType};

pub fn extract_claims(doc: &serde_json::Value, schema: &[ClaimSchema]) -> Vec<Claim> {
    let mut claims = Vec::new();

    match doc {
        serde_json::Value::Object(map) => {
            for field_def in schema {
                if let Some(value) = extract_field_value(map, &field_def.field_name) {
                    let normalized = normalize_value(&value, &field_def.value_type);
                    claims.push(Claim::new(&field_def.field_name, "has_value", &normalized));
                }
            }
        }
        _ => {}
    }

    claims
}

fn extract_field_value(map: &serde_json::Map<String, serde_json::Value>, field: &str) -> Option<String> {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current: &serde_json::Value = &serde_json::Value::Object(map.clone());

    for part in parts {
        match current {
            serde_json::Value::Object(m) => {
                current = m.get(part)?;
            }
            _ => return None,
        }
    }

    Some(value_to_string(current))
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

pub fn normalize_value(value: &str, value_type: &ValueType) -> String {
    let trimmed = value.trim();

    match value_type {
        ValueType::Currency => normalize_currency(trimmed),
        ValueType::Date => normalize_date(trimmed),
        ValueType::Number => normalize_number(trimmed),
        ValueType::Text | ValueType::Email => {
            use unicode_normalization::UnicodeNormalization;
            let nfc: String = trimmed.nfc().collect();
            nfc.split_whitespace()
                .collect::<Vec<&str>>()
                .join(" ")
                .to_lowercase()
        }
    }
}

fn normalize_currency(s: &str) -> String {
    let (amount, currency) = parse_currency(s);
    format!("{} {}", format!("{:.2}", amount), currency)
}

fn parse_currency(s: &str) -> (f64, String) {
    let symbols = [("€", "EUR"), ("$", "USD"), ("£", "GBP"), ("¥", "JPY")];

    for (symbol, code) in &symbols {
        if let Some(pos) = s.find(symbol) {
            let num_part = if pos == 0 { &s[symbol.len()..] } else { &s[..pos] };
            let amount = parse_number_str(num_part);
            return (amount, code.to_string());
        }
    }

    let code_patterns = ["EUR", "USD", "GBP", "JPY", "CHF"];
    for code in &code_patterns {
        if s.contains(code) {
            let num_part = s.replace(code, "").trim().to_string();
            let amount = parse_number_str(&num_part);
            return (amount, code.to_string());
        }
    }

    (parse_number_str(s), "UNKNOWN".to_string())
}

fn parse_number_str(s: &str) -> f64 {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
    cleaned.parse().unwrap_or(0.0)
}

fn normalize_date(s: &str) -> String {
    let formats = [
        "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d.%m.%Y",
        "%d-%m-%Y", "%B %d, %Y", "%d %B %Y", "%Y/%m/%d",
    ];

    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(
            &format!("{} 00:00:00", s), &format!("{} %H:%M:%S", fmt),
        ) {
            return dt.format("%Y-%m-%d").to_string();
        }
        if let Ok(dt) = chrono::NaiveDate::parse_from_str(s, fmt) {
            return dt.format("%Y-%m-%d").to_string();
        }
    }

    s.to_lowercase().trim().to_string()
}

fn normalize_number(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
    if let Ok(n) = cleaned.parse::<f64>() {
        if n == n.floor() {
            format!("{}", n as i64)
        } else {
            format!("{:.2}", n)
        }
    } else {
        s.to_lowercase().trim().to_string()
    }
}

pub fn hash_claim(claim: &Claim) -> [u8; 32] {
    let canonical = claim.canonical_key();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

pub fn hash_claims(claims: &[Claim]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for claim in claims {
        hasher.update(hash_claim(claim));
    }
    hasher.finalize().into()
}
