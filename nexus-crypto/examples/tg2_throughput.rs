//! Cinco repeticiones por número de hilos; resultados crudos en CSV.
#[path = "../experiments/tg2_throughput.rs"]
mod experiment;

use nexus_core::NexusError;
use std::{fs::File, io::Write, time::Duration};

fn main() -> Result<(), NexusError> {
    let directory = std::env::args().nth(1).ok_or_else(||
        NexusError::ConfigError("Uso: tg2_throughput <directorio de salida>".into()))?;
    let directory = std::path::Path::new(&directory);
    std::fs::create_dir_all(directory)?;
    let batch = experiment::prepare_batch(4096)?;
    std::fs::write(directory.join("corpus-publico.bin"), bincode::serialize(&batch)?)?;
    let maximum = std::thread::available_parallelism()?.get();
    let mut points = vec![1, 2, 4, 8, 12, 16, 20, maximum];
    points.retain(|&point| point <= maximum);
    points.sort_unstable();
    points.dedup();
    let mut output = File::create(directory.join("throughput.csv"))?;
    writeln!(output, "repetition,threads,verifications,elapsed_ns,verifications_per_second,worker_counts")?;
    for repetition in 1..=5 {
        let order: Vec<_> = if repetition % 2 == 0 { points.iter().rev().copied().collect() } else { points.clone() };
        for workers in order {
            let trial = experiment::measure(&batch, workers, Duration::from_secs(1))?;
            let counts = trial.worker_counts.iter().map(u64::to_string).collect::<Vec<_>>().join(";");
            writeln!(output, "{repetition},{workers},{},{},{:.6},{counts}",
                trial.count, trial.elapsed_ns, trial.verifications_per_second())?;
            output.flush()?;
            println!("repeticion={repetition}; hilos={workers}; verif_s={:.1}", trial.verifications_per_second());
        }
    }
    Ok(())
}
