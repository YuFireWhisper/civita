use std::hint::black_box;

use civita_core::consensus::block::tree::dag::{Dag, Node};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

#[derive(Clone)]
#[derive(Debug)]
struct TestNode {
    id: u32,
    validation_complexity: usize,
}

impl TestNode {
    fn new(id: u32) -> Self {
        Self {
            id,
            validation_complexity: 1,
        }
    }

    fn with_complexity(mut self, complexity: usize) -> Self {
        self.validation_complexity = complexity;
        self
    }
}

impl Node for TestNode {
    type Id = u32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn validate(&self) -> bool {
        true
    }

    fn on_parent_valid(&self, _child: &Self) -> bool {
        true
    }
}

fn bench_dag_update_single_node(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag.upsert_single");

    for complexity in [1, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("complexity", complexity),
            &complexity,
            |b, &complexity| {
                b.iter(|| {
                    let mut dag = Dag::new();
                    let node = TestNode::new(1).with_complexity(complexity);
                    black_box(dag.upsert(node, vec![]));
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_linear_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_linear_chain");

    for chain_length in [10, 50, 100, 500, 1000] {
        group.bench_with_input(
            BenchmarkId::new("length", chain_length),
            &chain_length,
            |b, &chain_length| {
                b.iter(|| {
                    let mut dag = Dag::new();

                    for i in 1..=chain_length {
                        let node = TestNode::new(i);
                        let parent_ids = vec![if i == 1 { 0 } else { i - 1 }];
                        black_box(dag.upsert(node, parent_ids));
                    }
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_fan_out(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_fan_out");

    for fan_out_size in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("fan_out", fan_out_size),
            &fan_out_size,
            |b, &fan_out_size| {
                b.iter(|| {
                    let mut dag = Dag::new();

                    let root = TestNode::new(0);
                    dag.upsert(root, vec![]);

                    for i in 1..=fan_out_size {
                        let node = TestNode::new(i);
                        black_box(dag.upsert(node, vec![0]));
                    }
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_fan_in(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_fan_in");

    for fan_in_size in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("fan_in", fan_in_size),
            &fan_in_size,
            |b, &fan_in_size| {
                b.iter(|| {
                    let mut dag = Dag::new();

                    for i in 0..fan_in_size {
                        let node = TestNode::new(i);
                        dag.upsert(node, vec![0]);
                    }

                    let child = TestNode::new(fan_in_size);
                    let parent_ids: Vec<u32> = (0..fan_in_size).collect();
                    black_box(dag.upsert(child, parent_ids));
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_complex_structure(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_complex_structure");

    for layers in [3, 5, 7, 10] {
        group.bench_with_input(BenchmarkId::new("layers", layers), &layers, |b, &layers| {
            b.iter(|| {
                let mut dag = Dag::new();
                let nodes_per_layer = 10;
                let mut node_id = 0u32;

                let mut current_layer_nodes = Vec::new();

                for _ in 0..nodes_per_layer {
                    let node = TestNode::new(node_id);
                    current_layer_nodes.push(node_id);
                    dag.upsert(node, vec![]);
                    node_id += 1;
                }

                for _ in 1..layers {
                    let mut next_layer_nodes = Vec::new();

                    for _ in 0..nodes_per_layer {
                        let node = TestNode::new(node_id);
                        next_layer_nodes.push(node_id);

                        let num_parents = (current_layer_nodes.len() / 2).max(1);
                        let parent_ids: Vec<u32> = current_layer_nodes
                            .iter()
                            .take(num_parents)
                            .cloned()
                            .collect();

                        black_box(dag.upsert(node, parent_ids));
                        node_id += 1;
                    }

                    current_layer_nodes = next_layer_nodes;
                }
            })
        });
    }
    group.finish();
}

fn bench_dag_node_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_node_updates");

    for dag_size in [100, 500, 1000] {
        group.bench_with_input(
            BenchmarkId::new("size", dag_size),
            &dag_size,
            |b, &dag_size| {
                let mut dag = Dag::new();
                for i in 1..=dag_size {
                    let node = TestNode::new(i);
                    let parent_ids = vec![if i == 1 { 0 } else { i - 1 }];
                    dag.upsert(node, parent_ids);
                }

                b.iter(|| {
                    let middle_id = dag_size / 2;
                    let updated_node = TestNode::new(middle_id).with_complexity(10);
                    black_box(dag.upsert(updated_node, vec![middle_id - 1]));
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_memory");

    for dag_size in [1000, 5000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("size", dag_size),
            &dag_size,
            |b, &dag_size| {
                b.iter(|| {
                    let mut dag = Dag::new();

                    let mut current_level = vec![0u32];
                    dag.upsert(TestNode::new(0), vec![]);
                    let mut next_id = 1;

                    while next_id < dag_size {
                        let mut next_level = Vec::new();

                        for &parent_id in &current_level {
                            for _ in 0..2 {
                                if next_id >= dag_size {
                                    break;
                                }

                                let node = TestNode::new(next_id);
                                dag.upsert(node, vec![parent_id]);
                                next_level.push(next_id);
                                next_id += 1;
                            }
                            if next_id >= dag_size {
                                break;
                            }
                        }

                        current_level = next_level;
                        if current_level.is_empty() {
                            break;
                        }
                    }

                    black_box(dag)
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_error_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_error_handling");

    group.bench_function("cycle_detection", |b| {
        b.iter(|| {
            let mut dag = Dag::new();

            dag.upsert(TestNode::new(1), vec![]);
            dag.upsert(TestNode::new(2), vec![1]);
            dag.upsert(TestNode::new(3), vec![2]);

            let cyclic_node = TestNode::new(1);
            black_box(dag.upsert(cyclic_node, vec![3]))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dag_update_single_node,
    bench_dag_linear_chain,
    bench_dag_fan_out,
    bench_dag_fan_in,
    bench_dag_complex_structure,
    bench_dag_node_updates,
    bench_dag_memory_usage,
    bench_dag_error_handling,
);

criterion_main!(benches);
