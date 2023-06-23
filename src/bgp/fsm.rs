use log::{debug};
use std::time::Instant;
use routecore::bgp::message::OpenMessage;
use bytes::Bytes;

// The SessionAttributes struct keeps track of all the
// parameters/counters/values as described in RFC4271. Fields that we
// introduce ourselves, e.g. the _tick fields to keep track of timers, carry
// the comment 'routecore'.
// Such fields, specific to the routecore implementation of the FSM, might
// eventually render other fields in the struct obsolete. For the _tick
// fields, that would be the corresponding _timer fields, most likely.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
// XXX make SessionAttributes generic over marker::PhantomData for State and
// leverage the type system with impl From's ? 
pub struct SessionAttributes {
    // mandatory
    
    state: State, // nr 1, etc
                  //
    connect_retry_counter: usize,

    connect_retry_timer: u16, //current value
    connect_retry_time: u16,  // initial value
    connect_retry_last_tick: Option<Instant>, // routecore. If counter
                                              // started, then this fields
                                              // contains Some(last_tick).
                                              // If now() - last_tick >
                                              // retry_time, the timeout is
                                              // exceeded.
                              
    hold_timer: u16,         // current value
    hold_time: u16,          // initial value
                             //
    keepalive_timer: u16,
    keepalive_time: u16, //nr 8

    // optional
/*
    AcceptConnectionsUnconfiguredPeers, // nr 1, etc
    AllowAutomaticStart,
    AllowAutomaticStop,
    CollisionDetectEstablishedState,
    DampPeerOscillations, // group 2
    // group 1
    DelayOpen,
    DelayOpenTime,
    DelayOpenTimer,
    // --
    IdleHoldTime, // group 2
    IdleHoldTimer, // group 2
    PassiveTcpEstablishment,
    SendNOTIFICATIONwithoutOPEN,
    TrackTcpState, // nr 13
*/
}

impl SessionAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn hold_time(&self) -> u16 {
        self.hold_time
    }
    pub fn set_hold_time(&mut self, hold_time: u16) {
        self.hold_time = hold_time;
    }

    pub fn state(self) -> State {
        self.state
    }

    pub fn connect_retry_tick(&mut self, t: Instant) {
        self.connect_retry_last_tick = Some(t);
    }
    pub fn reset_connect_retry(&mut self) {
        self.connect_retry_counter = 0;
    }
    pub fn stop_connect_retry(&mut self) {
        self.connect_retry_last_tick = None;
    }

    pub fn increase_connect_retry_counter(&mut self) {
        self.connect_retry_counter += 1;
    }

    pub fn set_state(&mut self, state: State) {
        debug!("FSM {:?} -> {:?}", &self.state, state);
        self.state = state;
    }
}

impl Default for SessionAttributes {
    fn default() -> Self {
        SessionAttributes {
            state: State::Idle,
            connect_retry_counter: 0,
            connect_retry_timer: 120,
            connect_retry_time: 120,
            connect_retry_last_tick: None,
            hold_timer: 90,
            hold_time: 90,
            keepalive_timer: 180,
            keepalive_time: 180,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Clone, Debug)]
pub enum Event {
    // mandatory
    ManualStart, // 1
    ManualStop, // 2

    /*  events 3 - 8
    // optional
    AutomaticStart, 
    ManualStartWithPassiveTcpEstablishment,
    AutomaticStartWithPassiveTcpEstablishment,
    AutomaticStartWithDampPeerOscillations,
    AutomaticStartWithDampPeerOscillationsAndPassiveTcpEstablishment,
    AutomaticStop,
    */


    // mandatory timer events

    ConnectRetryTimerExpires, // 9
    HoldTimerExpires, // 10
    KeepaliveTimerExpires, // 11

    /*
    // optional timer events
    DelayOpenTimerExpires, // 12
    IdleHoldTimerExpires, // 13
    */

    /*
    // optional TCP connection-based events
    TcpConnectionValid, // 14
    TcpCrInvalid, //15
    */

    // mandatory TCP connection-based events
    TcpCrAcked, // 16
    TcpConnectionConfirmed, // 17
    TcpConnectionFails, // 18


    // mandatory BGP message-based events
    BgpOpen(OpenMessage<Bytes>), // 19

    BgpHeaderErr, // 21
    BgpOpenMsgErr, // 22

    NotifMsgVerErr, // 24
    NotifMsg, // 25
    KeepaliveMsg, // 26
    UpdateMsg, // 27
    UpdateMsgErr, // 28


    /*
    // optional BGP message-based events
    
    BgpOpenWithDelayOpenTimerRunning, // event 20
    OpenCollisionDump, // event 23
    */

}



