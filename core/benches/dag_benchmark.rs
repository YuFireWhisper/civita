use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use civita_core::consensus::block::tree::dag::*;

const SIZES: [usize; 3] = [100, 500, 1000];

struct TestNode {
    id: u32,
    valid: bool,
    parent_constraint: Option<Box<dyn Fn(u32) -> bool + Send + Sync>>,
}

impl TestNode {
    fn new(id: u32, valid: bool) -> Self {
        Self {
            id,
            valid,
            parent_constraint: None,
        }
    }
}

impl Node for TestNode {
    type Id = u32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn validate(&self) -> bool {
        self.valid
    }

    fn on_parent_valid(&self, parent: &Self) -> bool {
        match &self.parent_constraint {
            Some(constraint) => constraint(parent.id()),
            None => true,
        }
    }
}

// 拓撲結構生成器
struct TopologyGenerator {
    rng: StdRng,
}

impl TopologyGenerator {
    fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }

    // 線性鏈: 0 -> 1 -> 2 -> ... -> n-1
    fn linear_chain(&mut self, size: usize, valid_ratio: f32) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = Vec::new();

        for i in 0..size {
            let valid = self.rng.random::<f32>() < valid_ratio;
            let node = TestNode::new(i as u32, valid);
            let parents = if i == 0 { vec![] } else { vec![(i - 1) as u32] };
            nodes.push((node, parents));
        }

        nodes
    }

    // 扇出: 一個根節點連接到所有其他節點
    fn fan_out(&mut self, size: usize, valid_ratio: f32) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = Vec::new();

        for i in 0..size {
            let valid = self.rng.random::<f32>() < valid_ratio;
            let node = TestNode::new(i as u32, valid);
            let parents = if i == 0 { vec![] } else { vec![0] };
            nodes.push((node, parents));
        }

        nodes
    }

    // 扇入: 所有節點都連接到最後一個節點
    fn fan_in(&mut self, size: usize, valid_ratio: f32) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = Vec::new();

        for i in 0..size {
            let valid = self.rng.random::<f32>() < valid_ratio;
            let node = TestNode::new(i as u32, valid);
            let parents = if i == size - 1 {
                (0..i).map(|x| x as u32).collect()
            } else {
                vec![]
            };
            nodes.push((node, parents));
        }

        nodes
    }

    // 平衡樹
    fn balanced_tree(&mut self, size: usize, valid_ratio: f32) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = Vec::new();

        for i in 0..size {
            let valid = self.rng.random::<f32>() < valid_ratio;
            let node = TestNode::new(i as u32, valid);
            let parents = if i == 0 {
                vec![]
            } else {
                vec![((i - 1) / 2) as u32]
            };
            nodes.push((node, parents));
        }

        nodes
    }

    // 複雜網狀結構
    fn complex_graph(
        &mut self,
        size: usize,
        valid_ratio: f32,
        density: f32,
    ) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = Vec::new();

        for i in 0..size {
            let valid = self.rng.random::<f32>() < valid_ratio;
            let node = TestNode::new(i as u32, valid);

            let mut parents = Vec::new();
            for j in 0..i {
                if self.rng.random::<f32>() < density {
                    parents.push(j as u32);
                }
            }

            nodes.push((node, parents));
        }

        nodes
    }

    // 帶循環的結構（會被DAG拒絕）
    fn with_cycles(&mut self, size: usize, valid_ratio: f32) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = self.linear_chain(size, valid_ratio);

        // 添加一些循環
        if size > 2 {
            // 讓最後一個節點指向第一個節點
            nodes.last_mut().unwrap().1.push(0);

            // 添加一些隨機循環
            for _ in 0..(size / 10) {
                let from = self.rng.random_range(0..size);
                let to = self.rng.random_range(0..from.max(1));
                nodes[from].1.push(to as u32);
            }
        }

        nodes
    }

    // 孤立子圖
    fn isolated_subgraphs(
        &mut self,
        size: usize,
        valid_ratio: f32,
        num_components: usize,
    ) -> Vec<(TestNode, Vec<u32>)> {
        let mut nodes = Vec::new();
        let component_size = size / num_components;

        for comp in 0..num_components {
            let start = comp * component_size;
            let end = if comp == num_components - 1 {
                size
            } else {
                (comp + 1) * component_size
            };

            for i in start..end {
                let valid = self.rng.random::<f32>() < valid_ratio;
                let node = TestNode::new(i as u32, valid);
                let parents = if i == start {
                    vec![]
                } else {
                    vec![(i - 1) as u32]
                };
                nodes.push((node, parents));
            }
        }

        nodes
    }
}

// 插入模式
#[derive(Clone, Copy)]
enum InsertionPattern {
    Sequential,
    Reverse,
    Random,
    Batch,
}

fn apply_insertion_pattern(
    nodes: Vec<(TestNode, Vec<u32>)>,
    pattern: InsertionPattern,
    rng: &mut StdRng,
) -> Vec<(TestNode, Vec<u32>)> {
    match pattern {
        InsertionPattern::Sequential => nodes,
        InsertionPattern::Reverse => {
            let mut reversed = nodes;
            reversed.reverse();
            reversed
        }
        InsertionPattern::Random => {
            let mut shuffled = nodes;
            for i in (1..shuffled.len()).rev() {
                let j = rng.random_range(0..=i);
                shuffled.swap(i, j);
            }
            shuffled
        }
        InsertionPattern::Batch => {
            let mut batched = nodes;
            let batch_size = (batched.len() / 4).max(1);

            for chunk in batched.chunks_mut(batch_size) {
                for i in (1..chunk.len()).rev() {
                    let j = rng.random_range(0..=i);
                    chunk.swap(i, j);
                }
            }
            batched
        }
    }
}

fn generate_phantom_waiting_scenario(size: usize, valid_ratio: f32) -> Vec<(TestNode, Vec<u32>)> {
    let mut nodes = Vec::new();

    for i in 1..size {
        let valid = rand::rng().random::<f32>() < valid_ratio;
        let node = TestNode::new(i as u32, valid);
        let parents = vec![0];
        nodes.push((node, parents));
    }

    let root = TestNode::new(0, true);
    nodes.push((root, vec![]));

    nodes
}

// 基準測試函數
fn benchmark_upsert_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("upsert_sequential");

    for &size in &SIZES {
        group.bench_with_input(BenchmarkId::new("linear_chain", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let mut gen = TopologyGenerator::new(42);
                    gen.linear_chain(size, 1.0)
                },
                |nodes| {
                    let mut dag = Dag::new();
                    for (node, parents) in nodes {
                        black_box(dag.upsert(node, parents));
                    }
                    dag
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("fan_in", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let mut gen = TopologyGenerator::new(42);
                    gen.fan_in(size, 1.0)
                },
                |nodes| {
                    let mut dag = Dag::new();
                    for (node, parents) in nodes {
                        black_box(dag.upsert(node, parents));
                    }
                    dag
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("fan_out", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let mut gen = TopologyGenerator::new(42);
                    gen.fan_out(size, 1.0)
                },
                |nodes| {
                    let mut dag = Dag::new();
                    for (node, parents) in nodes {
                        black_box(dag.upsert(node, parents));
                    }
                    dag
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(
            BenchmarkId::new("complex_graph", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mut gen = TopologyGenerator::new(42);
                        gen.complex_graph(size, 1.0, 0.1)
                    },
                    |nodes| {
                        let mut dag = Dag::new();
                        for (node, parents) in nodes {
                            black_box(dag.upsert(node, parents));
                        }
                        dag
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_upsert_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("upsert_insertion_patterns");
    let size = 1000;

    for &pattern in &[
        InsertionPattern::Sequential,
        InsertionPattern::Reverse,
        InsertionPattern::Random,
        InsertionPattern::Batch,
    ] {
        let pattern_name = match pattern {
            InsertionPattern::Sequential => "sequential",
            InsertionPattern::Reverse => "reverse",
            InsertionPattern::Random => "random",
            InsertionPattern::Batch => "batch",
        };

        group.bench_with_input(
            BenchmarkId::new(pattern_name, size),
            &pattern,
            |b, &pattern| {
                b.iter_batched(
                    || {
                        let mut gen = TopologyGenerator::new(42);
                        let mut rng = StdRng::seed_from_u64(42);
                        let nodes = gen.balanced_tree(size, 1.0);
                        apply_insertion_pattern(nodes, pattern, &mut rng)
                    },
                    |nodes| {
                        let mut dag = Dag::new();
                        for (node, parents) in nodes {
                            black_box(dag.upsert(node, parents));
                        }
                        dag
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn benchmark_upsert_validity_ratios(c: &mut Criterion) {
    let mut group = c.benchmark_group("upsert_validity_ratios");
    let size = 1000;

    for &ratio in &[1.0, 0.5, 0.1] {
        let ratio_name = match ratio {
            1.0 => "all_valid",
            0.5 => "half_valid",
            0.1 => "sparse_valid",
            _ => "other",
        };

        group.bench_with_input(BenchmarkId::new(ratio_name, size), &ratio, |b, &ratio| {
            b.iter_batched(
                || {
                    let mut gen = TopologyGenerator::new(42);
                    gen.balanced_tree(size, ratio)
                },
                |nodes| {
                    let mut dag = Dag::new();
                    for (node, parents) in nodes {
                        black_box(dag.upsert(node, parents));
                    }
                    dag
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn benchmark_upsert_special_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("upsert_special_cases");
    let size = 1000;

    // 循環檢測
    group.bench_with_input(BenchmarkId::new("with_cycles", size), &size, |b, &size| {
        b.iter_batched(
            || {
                let mut gen = TopologyGenerator::new(42);
                gen.with_cycles(size, 1.0)
            },
            |nodes| {
                let mut dag = Dag::new();
                for (node, parents) in nodes {
                    black_box(dag.upsert(node, parents));
                }
                dag
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // 孤立子圖
    group.bench_with_input(
        BenchmarkId::new("isolated_subgraphs", size),
        &size,
        |b, &size| {
            b.iter_batched(
                || {
                    let mut gen = TopologyGenerator::new(42);
                    gen.isolated_subgraphs(size, 1.0, 5)
                },
                |nodes| {
                    let mut dag = Dag::new();
                    for (node, parents) in nodes {
                        black_box(dag.upsert(node, parents));
                    }
                    dag
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    // Phantom waiting場景
    group.bench_with_input(
        BenchmarkId::new("phantom_waiting", size),
        &size,
        |b, &size| {
            b.iter_batched(
                || generate_phantom_waiting_scenario(size, 1.0),
                |nodes| {
                    let mut dag = Dag::new();
                    for (node, parents) in nodes {
                        black_box(dag.upsert(node, parents));
                    }
                    dag
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    benchmark_upsert_sequential,
    benchmark_upsert_patterns,
    benchmark_upsert_validity_ratios,
    benchmark_upsert_special_cases,
);

criterion_main!(benches);
