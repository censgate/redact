//! Randomized scan fixture. Seed is printed first.

use rand::{Rng, RngExt, SeedableRng};
use sqlx::PgPool;

/// Known PII and clean columns created for a run.
pub struct Fixture {
    pub pii: Vec<(String, String)>,
    pub clean: Vec<(String, String)>,
    pub secret_values: Vec<String>,
}

impl Fixture {
    pub fn generate(seed: u64) -> (Self, Vec<String>) {
        eprintln!("redact-scan fixture seed={seed:#x}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut sql = Vec::new();
        let mut pii = Vec::new();
        let mut clean = Vec::new();
        let mut secret_values = Vec::new();

        let t_pii = ident(&mut rng, "t");
        let t_clean = ident(&mut rng, "t");
        let c_email = ident(&mut rng, "c");
        let c_ssn = ident(&mut rng, "c");
        let c_iban = ident(&mut rng, "c");
        let c_cc = ident(&mut rng, "c");
        let c_ip = ident(&mut rng, "c");
        let c_json = ident(&mut rng, "c");
        let c_status = ident(&mut rng, "c");
        let c_qty = ident(&mut rng, "c");
        let c_note = ident(&mut rng, "c");
        let c_flag = ident(&mut rng, "c");

        sql.push(format!(
            "CREATE TABLE {t_pii} ({c_email} text, {c_ssn} text, {c_iban} text, {c_cc} text, {c_ip} inet, {c_json} jsonb)"
        ));
        sql.push(format!(
            "CREATE TABLE {t_clean} ({c_status} text, {c_qty} int, {c_note} text, {c_flag} boolean)"
        ));

        let email = format!("user{seed}@example.test");
        let ssn = "856-45-6789";
        let iban = "GB82WEST12345698765432";
        let cc = "4111111111111111";
        let ip = "203.0.113.10";
        let json = format!(r#"{{"customer":{{"email":"{email}"}},"{email}":"note"}}"#);
        secret_values.extend([email.clone(), ssn.into(), iban.into(), cc.into(), ip.into()]);

        // Repeat a subset so ANALYZE fills most_common_vals.
        for _ in 0..40 {
            sql.push(format!(
                "INSERT INTO {t_pii} ({c_email},{c_ssn},{c_iban},{c_cc},{c_ip},{c_json}) VALUES ('{email}','{ssn}','{iban}','{cc}','{ip}','{json}')"
            ));
        }
        // Unique emails so histogram_bounds also holds values.
        for i in 0..20 {
            let unique = format!("uniq{seed}{i}@example.test");
            secret_values.push(unique.clone());
            sql.push(format!(
                "INSERT INTO {t_pii} ({c_email},{c_ssn},{c_iban},{c_cc},{c_ip},{c_json}) VALUES ('{unique}','{ssn}','{iban}','{cc}','{ip}','{json}')"
            ));
        }
        for _ in 0..30 {
            let status = if rng.random_bool(0.5) {
                "active"
            } else {
                "pending"
            };
            sql.push(format!(
                "INSERT INTO {t_clean} ({c_status},{c_qty},{c_note},{c_flag}) VALUES ('{status}',{},'lorem ipsum dolor sit amet',true)",
                rng.random_range(1..100)
            ));
        }

        pii.extend([
            (t_pii.clone(), c_email),
            (t_pii.clone(), c_ssn),
            (t_pii.clone(), c_iban),
            (t_pii.clone(), c_cc),
            (t_pii.clone(), c_ip),
            (t_pii, c_json),
        ]);
        clean.extend([
            (t_clean.clone(), c_status),
            (t_clean.clone(), c_qty),
            (t_clean.clone(), c_note),
            (t_clean, c_flag),
        ]);

        (
            Self {
                pii,
                clean,
                secret_values,
            },
            sql,
        )
    }
}

fn ident<R: Rng>(rng: &mut R, prefix: &str) -> String {
    format!("{prefix}_{:08x}", rng.random::<u32>())
}

pub async fn apply(pool: &PgPool, statements: &[String]) -> sqlx::Result<()> {
    for s in statements {
        let s = s.trim().trim_end_matches(';');
        if s.is_empty() {
            continue;
        }
        sqlx::query(s).execute(pool).await?;
    }
    Ok(())
}
