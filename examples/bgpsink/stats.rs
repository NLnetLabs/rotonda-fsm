use std::ops::{Add, AddAssign};
use rotonda_fsm::bgp::fsm::{SessionAttributes, State};

#[derive(Copy, Clone, Debug, Default)]
pub struct StatsReport {
    sessions_established: u32,
    updates_received: u32,
}

impl StatsReport {
    pub fn new() -> Self {
        StatsReport::default()
    }
}
impl Add for StatsReport {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        Self {
            sessions_established: self.sessions_established + other.sessions_established,
            updates_received: self.updates_received + other.updates_received,
        }
    }
}
impl AddAssign for StatsReport {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}
impl Add<SessionAttributes> for StatsReport {
    type Output = Self;
    fn add(self, other: SessionAttributes) -> Self::Output {
        Self {
            sessions_established: match other.state() {
                State::Established => self.sessions_established + 1,
                _ => self.sessions_established
            },
            ..self
        }
    }
}
impl AddAssign<SessionAttributes> for StatsReport {
    fn add_assign(&mut self, other: SessionAttributes) {
        *self = *self + other;
    }
}


