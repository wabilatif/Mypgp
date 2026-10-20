/*
** EPITECH PROJECT, 2026
** lib.rs
** File description:
** lib rust for get_primes
*/

use pyo3::prelude::*;

#[pyfunction]
fn get_primes(maximum: i64) -> PyResult<Vec<i64>> {
    let mut primes = vec![2];
    for num in (3..maximum).step_by(2) {
        let mut is_prime = true;
        let limit = (num as f64).sqrt() as i64;
        for &prime in &primes {
            if num % prime == 0 {
                is_prime = false;
                break;
            }
            if prime > limit {
                break;
            }
        }
        if is_prime {
            primes.push(num);
        }
    }
    Ok(primes)
}

#[pymodule]
fn my_rust_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_primes, m)?)?;
    Ok(())
}