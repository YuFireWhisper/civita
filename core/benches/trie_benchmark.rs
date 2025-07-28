use civita_core::utils::trie::{Record, Trie};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::collections::HashMap;

type TestHasher = sha2::Sha256;
type TestTrie = Trie<TestHasher>;

const SIZES: [usize; 3] = [100, 500, 1000];

fn generate_test_data(size: usize) -> Vec<(Vec<u8>, Record)> {
    (0..size)
        .map(|i| {
            let key = format!("test_key_{i:08}").into_bytes();
            let value = format!("test_value_{i:08}").into_bytes();
            let record = Record::new(i as u64 + 1, value);
            (key, record)
        })
        .collect()
}

fn generate_random_keys(size: usize, existing_ratio: f64) -> Vec<Vec<u8>> {
    let existing_count = (size as f64 * existing_ratio) as usize;
    let mut keys = Vec::new();

    for i in 0..existing_count {
        keys.push(format!("test_key_{i:08}").into_bytes());
    }

    for i in existing_count..size {
        keys.push(format!("non_existent_key_{i:08}").into_bytes());
    }

    let mut rng = StdRng::seed_from_u64(42);
    keys.shuffle(&mut rng);

    keys
}

fn bench_insert_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_insert");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("sequential_insert", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let mut trie = TestTrie::empty();
                    data.iter().for_each(|(key, record)| {
                        std::hint::black_box(trie.update(key, record.clone(), None));
                    });
                    std::hint::black_box(trie)
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("batch_insert", size), size, |b, &_size| {
            b.iter(|| {
                let mut trie = TestTrie::empty();
                let iters = data.iter().map(|(k, v)| (k.as_slice(), v.clone()));
                std::hint::black_box(trie.update_many(iters, None));
                std::hint::black_box(trie)
            });
        });
    }
    group.finish();
}

fn bench_get_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_get");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        let mut trie = TestTrie::empty();
        data.iter().for_each(|(key, record)| {
            trie.update(key, record.clone(), None);
        });
        trie.commit();

        let query_count = (*size).min(1000);
        let query_keys = generate_random_keys(query_count, 0.7);

        group.throughput(Throughput::Elements(query_keys.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("mixed_get", size),
            &(&trie, &query_keys),
            |b, (trie, keys)| {
                b.iter(|| {
                    keys.iter().for_each(|key| {
                        std::hint::black_box(trie.get(key));
                    });
                });
            },
        );

        let existing_keys: Vec<_> = data.iter().take(1000).map(|(k, _)| k.clone()).collect();
        group.bench_with_input(
            BenchmarkId::new("existing_keys_get", size),
            &(&trie, &existing_keys),
            |b, (trie, keys)| {
                b.iter(|| {
                    keys.iter().for_each(|key| {
                        std::hint::black_box(trie.get(key));
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_proof_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_proof");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        let mut trie = TestTrie::empty();
        data.iter().for_each(|(key, record)| {
            trie.update(key, record.clone(), None);
        });
        trie.commit();

        let proof_keys: Vec<_> = data
            .iter()
            .step_by((*size / 100).max(1))
            .map(|(k, _)| k.clone())
            .collect();

        group.throughput(Throughput::Elements(proof_keys.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("generate_proofs", size),
            &(&trie, &proof_keys),
            |b, (trie, keys)| {
                b.iter(|| {
                    let mut proof_db = HashMap::new();
                    keys.iter().for_each(|key| {
                        std::hint::black_box(trie.prove(key, &mut proof_db));
                    });
                    std::hint::black_box(proof_db)
                });
            },
        );
    }
    group.finish();
}

fn bench_verify_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_verify");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        let mut trie = TestTrie::empty();
        data.iter().for_each(|(key, record)| {
            trie.update(key, record.clone(), None);
        });
        trie.commit();

        let proof_count = (*size / 10).clamp(10, 100);
        let proof_keys: Vec<_> = data
            .iter()
            .take(proof_count)
            .map(|(k, _)| k.clone())
            .collect();

        let mut proof_db = HashMap::new();
        proof_keys.iter().for_each(|key| {
            trie.prove(key, &mut proof_db);
        });

        group.throughput(Throughput::Elements(proof_keys.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("verify_proofs", size),
            &(&trie, &proof_keys, &proof_db),
            |b, (trie, keys, proofs)| {
                b.iter(|| {
                    keys.iter().for_each(|key| {
                        std::hint::black_box(trie.verify_proof(key, proofs));
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_commit_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_commit");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("commit", size), size, |b, &_size| {
            b.iter_batched(
                || {
                    let mut trie = TestTrie::empty();
                    data.iter().for_each(|(key, record)| {
                        trie.update(key, record.clone(), None);
                    });
                    trie
                },
                |mut trie| std::hint::black_box(trie.commit()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_weight_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_weight");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        let mut trie = TestTrie::empty();
        data.iter().for_each(|(key, record)| {
            trie.update(key, record.clone(), None);
        });
        trie.commit();

        group.bench_with_input(
            BenchmarkId::new("calculate_weight", size),
            &trie,
            |b, trie| {
                b.iter(|| std::hint::black_box(trie.weight()));
            },
        );
    }
    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_memory");

    for size in SIZES.iter() {
        let data = generate_test_data(*size);

        group.bench_with_input(
            BenchmarkId::new("memory_footprint", size),
            &data,
            |b, data| {
                b.iter_batched(
                    TestTrie::empty,
                    |mut trie| {
                        data.iter().for_each(|(key, record)| {
                            trie.update(key, record.clone(), None);
                        });
                        trie.commit();
                        std::hint::black_box(trie)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_insert_operations,
    bench_get_operations,
    bench_proof_operations,
    bench_verify_operations,
    bench_commit_operations,
    bench_weight_operations,
    bench_memory_usage,
);

criterion_main!(benches);
