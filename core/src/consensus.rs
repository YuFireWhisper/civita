pub mod hot_stuff;
mod randomizer;

const THRESHOLD: f32 = 0.685;

#[cfg(not(test))]
const EXPECTED_MEMBERS: usize = 2000;

#[cfg(test)]
const EXPECTED_MEMBERS: usize = 100;

const THRESHOLD_MEMBERS: usize = (EXPECTED_MEMBERS as f32 * THRESHOLD) as usize;
