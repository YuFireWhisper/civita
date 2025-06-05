mod hot_stuff;

const THRESHOLD: f32 = 0.685;

const EXPECTED_MEMBERS: usize = 2000;
const THRESHOLD_MEMBERS: usize = (EXPECTED_MEMBERS as f32 * THRESHOLD) as usize;
