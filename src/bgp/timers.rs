use tokio::time::{interval, Interval, Instant};
use std::time::Duration;

use log::debug;

// TODO
//  - write out what all these do
//  - their relations 
//  - their recommended default values
//
// the fsm needs
//   hold timer
//   connect retry time
//   keepalive timer
//
//   and apparently, there is more:
//     MinASOriginationIntervalTimer (see Section 9.2.1.2), and
//     MinRouteAdvertisementIntervalTimer (see Section 9.2.1.1).
//
//   mentioned in 4271 as being optional:
//     group 1: DelayOpen, DelayOpenTime, DelayOpenTimer
//     group 2: DampPeerOscillations, IdleHoldTime, IdleHoldTimer
//
//

// Hold time: the smallest of the two Hold times exchanged in the BGP OPENs
// will be the hold time for the session, and must be 0 or >=3 seconds.
// When 0, no periodic KEEPALIVEs will be sent.
// If no UPDATE/KEEPALIVE/NOTIFICATION is received within the hold time, the
// BGP connection should be closed.
// Whenever an UPDATE/KEEPALIVE/NOTIFICATION is received, this timer is reset
// (if the negotiated time was not 0).
// Recommend value is 90s in 4271, though in early stages of the session this
// should be raised to 'a large value' (of 4 minutes).
//
// Connect retry timer: started when a TCP connection attempt is made. When
// expired, the current connection attempt is aborted, and a new connection is
// initialized.
//
// Keepalive timer is used to prevent the hold timer of the remote peer
// expiring. Upon expiration of the keepalive timer, a KEEPALIVE pdu is sent
// out, and the timer is reset. The keepalive timer is started after we've
// sent out our OPEN + KEEPALIVE to setup the session.
// It can be reset after each UPDATE/NOTIFICATION that we send out, though
// that is not explicitly written out in 4271.
// The period of the keepalive timer is typically 1/3 of the period of the
// Hold timer. Note that the hold timer is set to 'a large value' in early
// stages of the session.

#[derive(Debug)]
pub struct Timer {
    //orig_interval: Duration,
    started: bool,
    interval: Interval,
    last_tick: Instant,
}
impl Timer {
    pub fn new(secs: u64) -> Self {
        Self {
            //orig_interval: Duration::from_secs(secs),
            started: true,
            interval: interval(Duration::from_secs(secs)),
            last_tick: Instant::now(),
        }
    }

    pub async fn tick(&mut self) {
        self.last_tick = self.interval.tick().await;
    }

    pub fn start(&mut self) {
        //self.interval = interval(self.orig_interval);
        self.started = true;
        self.reset();
        let _ = self.interval.tick();
    }

    //pub fn stop(&mut self) {
    //    //self.interval = interval(Duration::ZERO);
    //    self.started = false;
    //}

    pub fn reset(&mut self) {
        self.interval.reset();
    }

    fn next_tick(&self) -> Instant {
        self.last_tick + self.interval.period()
    }

    pub fn until_next_tick(&self) -> Duration {
        self.next_tick() - Instant::now()
    }

    fn last_tick(&self) -> Instant {
        self.last_tick
    }

    pub fn since_last_tick(&self) -> Duration {
        //Instant::now().duration_since(self.last_tick)
        self.last_tick.elapsed()
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use tokio::time::{sleep, timeout};

    fn ptime() {
        println!("ptime: {:?}", Instant::now());
    }

    #[tokio::test]
    async fn works() {
        ptime();
        let mut t = Timer::new(1);
        t.start();
        ptime();
        let _ = t.tick().await;
        ptime();
        let _ = t.tick().await;
        ptime();
        let _ = t.tick().await;
        ptime();
        //t.stop();
        println!("{t:?}");
        //sleep(Duration::from_millis(2000)).await;

        if let Err(_) = timeout(Duration::from_secs(5), t.tick()).await {
            println!("did not receive value within 5s");
        }

        ptime();
        t.start();
        t.tick().await;
        ptime();

    }

}
