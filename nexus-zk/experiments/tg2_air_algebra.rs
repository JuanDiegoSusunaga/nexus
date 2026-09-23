//! Oráculo algebraico de referencia TG2, limitado a trazas pequeñas.
//! No sustituye FRI ni se integra en la ruta de aceptación del prototipo.
use nexus_zk::stark::field::{root_of_unity, Felt, Fp2, P};
use nexus_zk::stark::ntt::intt;

pub const MAX_ROWS: usize = 256;

#[derive(Clone, Debug)]
pub struct Division {
    pub quotient: Vec<Felt>,
    pub remainder: Vec<Felt>,
}

#[derive(Clone, Debug)]
pub struct Audit {
    pub rows: usize,
    pub coefficients: Vec<Felt>,
    pub divisions: [Division; 3],
    /// Numeradores elevados al denominador común X^T-1.
    pub numerators: [Vec<Felt>; 3],
}

#[derive(Clone, Debug)]
pub struct Composition {
    pub numerator: Vec<Fp2>,
    pub quotient: Vec<Fp2>,
    pub remainder: Vec<Fp2>,
}

fn trim(mut p: Vec<Felt>) -> Vec<Felt> {
    while p.last() == Some(&Felt::ZERO) { p.pop(); }
    p
}

pub fn degree(p: &[Felt]) -> Option<usize> {
    p.iter().rposition(|&c| c != Felt::ZERO)
}

pub fn degree_ext(p: &[Fp2]) -> Option<usize> {
    p.iter().rposition(|&c| c != Fp2::ZERO)
}

fn sub(a: &[Felt], b: &[Felt]) -> Vec<Felt> {
    let mut result = vec![Felt::ZERO; a.len().max(b.len())];
    for (i, &c) in a.iter().enumerate() { result[i] = result[i].add(c); }
    for (i, &c) in b.iter().enumerate() { result[i] = result[i].sub(c); }
    trim(result)
}

fn mul(a: &[Felt], b: &[Felt]) -> Vec<Felt> {
    if a.is_empty() || b.is_empty() { return Vec::new(); }
    let mut result = vec![Felt::ZERO; a.len()+b.len()-1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() { result[i+j] = result[i+j].add(x.mul(y)); }
    }
    trim(result)
}

fn shifted(a: &[Felt], factor: Felt) -> Vec<Felt> {
    let mut power = Felt::ONE;
    a.iter().map(|&c| {
        let value = c.mul(power);
        power = power.mul(factor);
        value
    }).collect()
}

fn divide(a: &[Felt], b: &[Felt]) -> Result<Division, String> {
    let divisor = trim(b.to_vec());
    let mut remainder = trim(a.to_vec());
    let Some(&leading) = divisor.last() else { return Err("Divisor nulo".into()); };
    let mut quotient = vec![Felt::ZERO; remainder.len().saturating_sub(divisor.len())+1];
    while remainder.len() >= divisor.len() {
        let Some(&last) = remainder.last() else { return Err("Resto inconsistente".into()); };
        let index = remainder.len()-divisor.len();
        let coefficient = last.mul(leading.inv());
        quotient[index] = coefficient;
        for (j, &value) in divisor.iter().enumerate() {
            remainder[index+j] = remainder[index+j].sub(coefficient.mul(value));
        }
        remainder = trim(remainder);
    }
    Ok(Division { quotient: trim(quotient), remainder })
}

/// Divide exactamente las restricciones de frontera y transición de una traza.
pub fn audit(trace: &[Felt], start: Felt, output: Felt) -> Result<Audit, String> {
    let t = trace.len();
    if t < 4 || t > MAX_ROWS || !t.is_power_of_two() {
        return Err("El oráculo admite potencias de dos entre 4 y 256 filas".into());
    }
    if trace.iter().any(|x| x.value() >= P) || start.value() >= P || output.value() >= P {
        return Err("El oráculo requiere elementos canónicos".into());
    }
    let g = root_of_unity(t.trailing_zeros());
    let last = g.pow((t-1) as u64);
    let penultimate = g.pow((t-2) as u64);
    let f = trim(intt(trace));
    let f_g = shifted(&f, g);
    let f_g2 = shifted(&f, g.mul(g));
    let transition = sub(&sub(&f_g2, &mul(&f_g, &f_g)), &mul(&f, &f));
    let initial = sub(&f, &[start]);
    let final_boundary = sub(&f, &[output]);
    let z0 = vec![Felt::ONE.neg(), Felt::ONE];
    let z1 = vec![last.neg(), Felt::ONE];
    let exceptions = mul(&z1, &[penultimate.neg(), Felt::ONE]);
    let mut common = vec![Felt::ZERO; t+1];
    common[0] = Felt::ONE.neg();
    common[t] = Felt::ONE;
    let zt = divide(&common, &exceptions)?;
    let factor0 = divide(&common, &z0)?;
    let factor1 = divide(&common, &z1)?;
    if !zt.remainder.is_empty() || !factor0.remainder.is_empty() || !factor1.remainder.is_empty() {
        return Err("Los factores no dividen el anulador".into());
    }
    Ok(Audit {
        rows: t,
        coefficients: f,
        divisions: [divide(&initial, &z0)?, divide(&final_boundary, &z1)?,
                    divide(&transition, &zt.quotient)?],
        numerators: [mul(&initial, &factor0.quotient), mul(&final_boundary, &factor1.quotient),
                     mul(&transition, &exceptions)],
    })
}

/// Combina numeradores y divide por X^T-1 en el campo de extensión.
pub fn compose(audit: &Audit, alphas: [Fp2; 3]) -> Composition {
    let mut numerator = vec![Fp2::ZERO; 2*audit.rows+1];
    for (poly, alpha) in audit.numerators.iter().zip(alphas) {
        for (i, &c) in poly.iter().enumerate() { numerator[i] = numerator[i].add(alpha.mul_base(c)); }
    }
    let mut remainder = numerator.clone();
    let mut quotient = vec![Fp2::ZERO; audit.rows+1];
    for i in (audit.rows..remainder.len()).rev() {
        let coefficient = remainder[i];
        quotient[i-audit.rows] = coefficient;
        remainder[i-audit.rows] = remainder[i-audit.rows].add(coefficient);
        remainder[i] = Fp2::ZERO;
    }
    remainder.truncate(audit.rows);
    Composition { numerator, quotient, remainder }
}

pub fn eval_ext(coefficients: &[Fp2], x: Felt) -> Fp2 {
    coefficients.iter().rev().fold(Fp2::ZERO, |v, &c| v.mul_base(x).add(c))
}

/// Fórmula local del AIR para contrastar el oráculo con aperturas del prototipo.
pub fn local_composition(
    rows: usize, start: Felt, output: Felt, alphas: [Fp2; 3], x: Felt, values: [Felt; 3],
) -> Result<Fp2, String> {
    if rows < 4 || rows > MAX_ROWS || !rows.is_power_of_two() {
        return Err("Tamaño fuera del oráculo algebraico".into());
    }
    let g = root_of_unity(rows.trailing_zeros());
    let last = g.pow((rows-1) as u64);
    let penultimate = g.pow((rows-2) as u64);
    let d = x.pow(rows as u64).sub(Felt::ONE);
    let d0 = x.sub(Felt::ONE);
    let d1 = x.sub(last);
    if d == Felt::ZERO || d0 == Felt::ZERO || d1 == Felt::ZERO {
        return Err("El punto pertenece a un polo excluido".into());
    }
    let transition = values[2].sub(values[1].mul(values[1])).sub(values[0].mul(values[0]));
    let parts = [
        values[0].sub(start).mul(d0.inv()),
        values[0].sub(output).mul(d1.inv()),
        transition.mul(x.sub(last)).mul(x.sub(penultimate)).mul(d.inv()),
    ];
    Ok(alphas.into_iter().zip(parts).fold(Fp2::ZERO, |a, (alpha, value)| a.add(alpha.mul_base(value))))
}
