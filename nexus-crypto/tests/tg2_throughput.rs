#[path = "../experiments/tg2_throughput.rs"]
mod experiment;

use std::time::Duration;

#[test]
fn coordinated_trial_counts_only_successful_work_and_covers_interval() {
    let batch = experiment::prepare_batch(8).unwrap();
    let duration = Duration::from_millis(20);
    let result = experiment::measure(&batch, 2, duration).unwrap();
    assert!(result.count > 0);
    assert_eq!(result.count, result.worker_counts.iter().sum::<u64>());
    assert!(result.elapsed_ns >= duration.as_nanos());
    assert_eq!(result.worker_counts.len(), 2);
    assert!(result.verifications_per_second().is_finite());
}

#[test]
fn invalid_work_aborts_measurement() {
    let mut batch = experiment::prepare_batch(1).unwrap();
    batch[0].1.push(0);
    assert!(experiment::measure(&batch, 2, Duration::from_millis(20)).is_err());
}

#[test]
fn invalid_measurement_parameters_are_rejected() {
    let batch = experiment::prepare_batch(1).unwrap();
    assert!(experiment::prepare_batch(0).is_err());
    assert!(experiment::measure(&[], 1, Duration::from_millis(1)).is_err());
    assert!(experiment::measure(&batch, 0, Duration::from_millis(1)).is_err());
    assert!(experiment::measure(&batch, 257, Duration::from_millis(1)).is_err());
    assert!(experiment::measure(&batch, 1, Duration::ZERO).is_err());
}
