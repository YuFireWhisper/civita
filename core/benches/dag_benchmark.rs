use std::{hint::black_box, sync::Arc};

use civita_core::consensus::block::tree::dag::{Dag, Node, State};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dashmap::DashMap;
use parking_lot::RwLock as ParkingRwLock;

#[derive(Clone)]
#[derive(Debug)]
struct TestNode {
    id: u32,
    state: State,
    parent_ids: Option<Vec<u32>>,
    validation_complexity: usize,
}

impl TestNode {
    fn new(id: u32, parent_ids: Option<Vec<u32>>) -> Self {
        Self {
            id,
            state: State::Pending,
            parent_ids,
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

    fn validate(&self, nodes: Arc<DashMap<Self::Id, Arc<ParkingRwLock<Self>>>>) -> State {
        let mut sum = 0u64;
        for i in 0..self.validation_complexity {
            sum = sum.wrapping_add(i as u64);
        }
        black_box(sum);

        if let Some(ref parent_ids) = self.parent_ids {
            for parent_id in parent_ids {
                if let Some(parent) = nodes.get(parent_id) {
                    if !parent.read().state().is_valid() && !parent.read().state().is_pending() {
                        return State::Invalid;
                    }
                } else {
                    return State::Invalid;
                }
            }
        }

        State::Valid
    }

    fn set_state(&mut self, state: State) {
        self.state = state;
    }

    fn parent_ids(&self) -> Option<Vec<Self::Id>> {
        self.parent_ids.clone()
    }

    fn state(&self) -> State {
        self.state
    }
}

fn bench_dag_update_single_node(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_update_single");

    for complexity in [1, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("complexity", complexity),
            &complexity,
            |b, &complexity| {
                b.iter(|| {
                    let mut dag = Dag::new();
                    let node = TestNode::new(1, None).with_complexity(complexity);
                    black_box(dag.update(node))
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
                        let parent_ids = if i == 1 { None } else { Some(vec![i - 1]) };
                        let node = TestNode::new(i, parent_ids);
                        black_box(dag.update(node));
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

                    let root = TestNode::new(0, None);
                    dag.update(root);

                    for i in 1..=fan_out_size {
                        let node = TestNode::new(i, Some(vec![0]));
                        black_box(dag.update(node));
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
                        let node = TestNode::new(i, None);
                        dag.update(node);
                    }

                    let parent_ids: Vec<u32> = (0..fan_in_size).collect();
                    let child = TestNode::new(fan_in_size, Some(parent_ids));
                    black_box(dag.update(child));
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
                    let node = TestNode::new(node_id, None);
                    current_layer_nodes.push(node_id);
                    dag.update(node);
                    node_id += 1;
                }

                for _ in 1..layers {
                    let mut next_layer_nodes = Vec::new();

                    for _ in 0..nodes_per_layer {
                        let num_parents = (current_layer_nodes.len() / 2).max(1);
                        let parent_ids: Vec<u32> = current_layer_nodes
                            .iter()
                            .take(num_parents)
                            .cloned()
                            .collect();

                        let node = TestNode::new(node_id, Some(parent_ids));
                        next_layer_nodes.push(node_id);
                        black_box(dag.update(node));
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
                    let parent_ids = if i == 1 { None } else { Some(vec![i - 1]) };
                    let node = TestNode::new(i, parent_ids);
                    dag.update(node);
                }

                b.iter(|| {
                    let middle_id = dag_size / 2;
                    let updated_node =
                        TestNode::new(middle_id, Some(vec![middle_id - 1])).with_complexity(10);
                    black_box(dag.update(updated_node))
                })
            },
        );
    }
    group.finish();
}

fn bench_dag_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_queries");

    let dag_size = 1000u32;
    let mut dag = Dag::new();

    for i in 1..=dag_size {
        let parent_ids = if i == 1 { None } else { Some(vec![i - 1]) };
        let node = TestNode::new(i, parent_ids);
        dag.update(node);
    }

    group.bench_function("get_parents", |b| {
        b.iter(|| {
            let middle_id = dag_size / 2;
            black_box(dag.get_parents(&middle_id))
        })
    });

    group.bench_function("get_children", |b| {
        b.iter(|| {
            let middle_id = dag_size / 2;
            black_box(dag.get_children(&middle_id))
        })
    });

    group.bench_function("has_path", |b| {
        b.iter(|| black_box(dag.has_path(&1, &dag_size)))
    });

    group.bench_function("topological_sort", |b| {
        b.iter(|| black_box(dag.topological_sort()))
    });

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
                    dag.update(TestNode::new(0, None));
                    let mut next_id = 1;

                    while next_id < dag_size {
                        let mut next_level = Vec::new();

                        for &parent_id in &current_level {
                            for _ in 0..2 {
                                if next_id >= dag_size {
                                    break;
                                }

                                let node = TestNode::new(next_id, Some(vec![parent_id]));
                                dag.update(node);
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

            dag.update(TestNode::new(1, None));
            dag.update(TestNode::new(2, Some(vec![1])));
            dag.update(TestNode::new(3, Some(vec![2])));

            let cyclic_node = TestNode::new(1, Some(vec![3]));
            black_box(dag.update(cyclic_node))
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
    bench_dag_queries,
    bench_dag_memory_usage,
    bench_dag_error_handling,
);

criterion_main!(benches);
