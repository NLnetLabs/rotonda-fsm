use std::time::Instant;
use std::net::IpAddr;

use octseq::Octets;
//use tokio::sync::mpsc;
use tokio::net::TcpStream;

use log::{debug, info, warn};
use routecore::asn::Asn;
use routecore::bgp::message::Message as BgpMsg;
use routecore::bgp::message::open::Capability;
use routecore::bgp::message::keepalive::KeepaliveBuilder;
use routecore::bgp::message::open::OpenBuilder;
use routecore::bgp::types::{AFI, SAFI};

use crate::bgp::fsm::{Event, SessionAttributes, State};

#[derive(Debug)]
pub struct Session {
    config: SessionConfig,
    attributes: SessionAttributes, // contains the actual FSM
    stream: Option<TcpStream>,
}

/// Local configuration of BGP session.
#[derive(Debug)]
pub struct SessionConfig {
    local_asn: Asn,
    bgp_id: [u8; 4],
    _remote_asn: Asn,
    remote_addr: IpAddr,
    capabilities: Vec<Capability<Vec<u8>>>,
}

impl Session {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            attributes: SessionAttributes::default(),
            stream: None,
        }
    }
    fn attach_stream(&mut self, stream: TcpStream) {
        self.stream = Some(stream);
    }

    pub fn try_for_connection(
        config: SessionConfig,
        connection: TcpStream
    ) -> Result<Self, ConnectionError> {
        if connection.peer_addr()?.ip() != config.remote_addr {
            return Err(ConnectionError)
        }
        let mut session = Self::new(config);
        session.attach_stream(connection);

        Ok(session)
    }

    fn send_raw(&self, raw: Vec<u8>) {
        if let Err(_) = self.stream.as_ref().unwrap().try_write(&raw) {
            warn!("failed to send_raw, connection borked?")
        }
    }

    pub fn send_open(&self) {
        let mut openbuilder = OpenBuilder::new_vec();
        openbuilder.set_asn(self.config.local_asn);
        openbuilder.set_holdtime(self.attributes.hold_time());
        openbuilder.set_bgp_id(self.config.bgp_id);

        // XXX these should come from our 'local config'
        for _c in &self.config.capabilities {
            // TODO add all capabilities
        }
        // for now, just fake these:
        openbuilder.add_mp(AFI::Ipv4, SAFI::Unicast);
        openbuilder.add_mp(AFI::Ipv6, SAFI::Unicast);

        // and for our bgpsink, we should copy all the capabilities
        // from the received OPEN

        self.send_raw(openbuilder.finish());
    }

    pub fn send_keepalive(&self) {
        self.send_raw(KeepaliveBuilder::new_vec().finish());
    }

    pub fn local_asn(&self) -> Asn {
        self.config.local_asn
    }

    pub fn attributes(&self) -> &SessionAttributes {
        &self.attributes
    }

    pub fn hold_time(&self) -> u16 {
        self.attributes().hold_time()
    }

    //pub fn set_hold_time(&mut self, time: u16) {
    //    self.attributes_mut().hold_time = time;
    //}

    fn attributes_mut(&mut self) -> &mut SessionAttributes {
        &mut self.attributes
    }

    pub fn state(&self) -> State {
        self.attributes.state()
    }

    fn start_connect_retry_timer(&mut self) {
       self.attributes_mut().connect_retry_tick(Instant::now());
    }

    fn stop_connect_retry_timer(&mut self) {
       self.attributes_mut().stop_connect_retry();
    }

    // XXX perhaps this should also do the corresonding _tick()?
    // XXX or maybe put this all in tokio sleep/timeouts ?
    fn increase_connect_retry_counter(&mut self) {
        //self.attributes_mut().connect_retry_counter += 1;
        self.attributes_mut().increase_connect_retry_counter();
    }

    fn reset_connect_retry_counter(&mut self) {
        //self.attributes_mut().connect_retry_counter = 0;
        self.attributes_mut().reset_connect_retry();
    }

    fn to_state(&mut self, state: State) {
        self.attributes_mut().to_state(state);
    }

    //--- event functions ----------------------------------------------------
    pub fn manual_start(&mut self) {
        self.handle_event(Event::ManualStart);
    }

    pub fn connection_established(&mut self) {
        self.handle_event(Event::TcpConnectionConfirmed);
    }

    pub fn handle_msg<Octs: Octets>(&mut self, msg: BgpMsg<Octs>) {
       match msg {
           BgpMsg::Open(_m) => {
               debug!("got OPEN, generating event");
               self.handle_event(Event::BgpOpen);
           }
           BgpMsg::Keepalive(_m) => {
               debug!("got KEEPALIVE, generating event");
               self.handle_event(Event::KeepaliveMsg);
           }
           BgpMsg::Update(_m) => {
               debug!("got UPDATE");
               self.handle_event(Event::UpdateMsg);
           }
           _ => todo!()
       }
    }

    //--- emitting over channel ----------------------------------------------
    //fn send_raw(&self, raw: T) {
    //fn send_raw(&self, raw: Vec<u8>) {
    //    //debug!("should send out {:?}...", &raw.as_ref()[..10]);
    //    let tx = self.channel.clone().unwrap();
    //    tokio::spawn( async move {
    //        tx.send(raw.to_vec()).await;
    //    });
    //}

    // state machine transitions
    fn handle_event(&mut self, event: Event) {
        use State as S;
        use Event as E;
        match (self.state(), event) {
            //--- Idle -------------------------------------------------------
            (S::Idle, E::ManualStart) => {

                //- initializes all BGP resources for the peer connection,
                // 
                
                //- sets ConnectRetryCounter to zero,
                self.attributes_mut().reset_connect_retry();

                //- starts the ConnectRetryTimer with the initial value,
                self.start_connect_retry_timer();

                //- initiates a TCP connection to the other BGP peer,
                // TODO, but, perhaps focus on
                // ManualStartWithPassiveTcpEstablishment first?

                //- listens for a connection that may be initiated by the remote
                //  BGP peer, and
                // TODO tokio listen 
                
                //- changes its state to Connect.
                self.to_state(State::Connect); 
            }
            (S::Idle, E::ManualStop) => {
                info!("ignored ManualStop in Idle state")
            }
            // optional events:
            //(S::Idle, E::AutomaticStart) => { ... }
            //(S::Idle, E::AutomaticStop) => { /* ignore */ }
            //(S::Idle, E::ManualStartWithPassiveTcpEstablishment) => { }
            //(S::Idle, E::AutomaticStartWithPassiveTcpEstablishment) => { }
            
            // if DampPeerOscillations is TRUE:
            //(S::Idle, E::AutomaticStartWithDampPeerOscillations) => { }
            //(S::Idle, E::AutomaticStartWithDampPeerOscillationsAndPassiveTcpEstablishment) => { }
            //(S::Idle, E::IdleHoldTimerExpires) => { }
            (S::Idle,
                E::ConnectRetryTimerExpires |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::TcpCrInvalid |
                E::TcpCrAcked |
                E::TcpConnectionConfirmed |
                E::TcpConnectionFails |
                E::BgpOpen |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr |
                E::NotifMsgVerErr |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
             ) => warn!("(unexpected) non-event {:?} in state Idle", event),

            //--- Connect ----------------------------------------------------
            (S::Connect, E::ManualStart /* | events 3-7 */ ) => {
                warn!("ignored {:?} in state Connect", event)
            }
            (S::Connect, E::ManualStop) => {
                // - drops the TCP connection,
                // TODO tokio
                
                // - releases all BGP resources,
                // TODO (is there something we need to do here?)

                // - sets ConnectRetryCounter to zero,
                self.attributes_mut().reset_connect_retry();

                // - stops the ConnectRetryTimer and sets ConnectRetryTimer to
                //   zero
                self.stop_connect_retry_timer();
                
                // - changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::Connect, E::ConnectRetryTimerExpires) => {
                todo!();
                //- drops the TCP connection,
                //- restarts the ConnectRetryTimer,
                //- stops the DelayOpenTimer and resets the timer to zero,
                //- initiates a TCP connection to the other BGP peer,
                //- continues to listen for a connection that may be initiated by
                //  the remote BGP peer, and
                //- stays in the Connect state.
            }
            // optional events:
            //(S::Connect, E::DelayOpenTimerExpires) => {}
            //(S::Connect, E::TcpConnectionValid) => {}
            //(S::Connect, E::TcpCrInvalid) => {}
            
            (S::Connect, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                let delayopen_implemented = false;
                //the local system checks the DelayOpen attribute prior to
                //processing.  If the DelayOpen attribute is set to TRUE, the
                //local system:
                if delayopen_implemented { 
                    todo!();
                    //  - stops the ConnectRetryTimer (if running) and sets
                    //  the ConnectRetryTimer to zero,
                    //  - sets the DelayOpenTimer to the initial value, and
                    //  - stays in the Connect state.
                    
                // If the DelayOpen attribute is set to FALSE, the local
                // system:
                } else {
                    //  - stops the ConnectRetryTimer (if running) and sets
                    //  the ConnectRetryTimer to zero,
                        self.stop_connect_retry_timer();

                    //  - completes BGP initialization
                    //  TODO (do we need to do something here?)

                    //  - sends an OPEN message to its peer,
                    //let to_send = self.handler.send_open(
                    //    //&self,
                    //    //self.local_asn,
                    //    //self.attributes().hold_time,
                    //    //self.bgp_id,
                    //);
                    self.send_open();


                    //  - set the HoldTimer to a large value (suggested: 4min)
                    //  TODO

                    //  - changes its state to OpenSent.
                    self.to_state(State::OpenSent);

                }

            }
            (S::Connect, E::TcpConnectionFails) => {
                let delayopen_implemented_and_running = false;
                if delayopen_implemented_and_running {
                    todo!();
                    //- restarts the ConnectRetryTimer with the initial value,
                    //- stops the DelayOpenTimer and resets its value to zero,
                    //- continues to listen for a connection that may be
                    //  initiated by the remote BGP peer, and
                    //- changes its state to Active.
                } else {
                    //- stops the ConnectRetryTimer to zero,
                    self.stop_connect_retry_timer();

                    //- drops the TCP connection,
                    // TODO tokio
                    
                    //- releases all BGP resources, and
                    // TODO something?
                    
                    //- changes its state to Idle.
                    self.to_state(State::Idle);
                }
            }
            // optional:
            //(S::Connect, E::BgpOpenWithDelayOpenTimerRunning) => {}
            (S::Connect, E::BgpHeaderErr | E::BgpOpenMsgErr) => { todo!() }
            (S::Connect, E::NotifMsgVerErr) => { todo!() }
            (S::Connect, 
                //E::AutomaticStop |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpen |
                //E::OpenCollisionDump |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- if the ConnectRetryTimer is running, stops and resets the
                //  ConnectRetryTimer (sets to zero),
                self.stop_connect_retry_timer();

                //- if the DelayOpenTimer is running, stops and resets the
                //  DelayOpenTimer (sets to zero),
                //  TODO

                //- releases all BGP resources,
                //  TODO anything?

                //- drops the TCP connection,
                //  TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- performs peer oscillation damping if the DampPeerOscillations
                //  attribute is set to True, and
                //  TODO

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }


            //--- Active -----------------------------------------------------
            (S::Active, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Active", event)
            }
            (S::Active, E::ManualStop) => {

                //- If the DelayOpenTimer is running and the
                //  SendNOTIFICATIONwithoutOPEN session attribute is set, the
                //  local system sends a NOTIFICATION with a Cease,
                //  TODO once the optional DelayOpenTimer is implemented

                //- releases all BGP resources including stopping the
                //  DelayOpenTimer
                //  TODO something?
                
                //- drops the TCP connection,
                // TODO tokio

                //- sets ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- stops the ConnectRetryTimer and sets the ConnectRetryTimer
                //  to zero
                self.stop_connect_retry_timer();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::Active, E::ConnectRetryTimerExpires) => {

                //- restarts the ConnectRetryTimer (with initial value),
                self.start_connect_retry_timer();

                //- initiates a TCP connection to the other BGP peer,
                // TODO tokio

                //- continues to listen for a TCP connection that may be
                //  initiated by a remote BGP peer
                //  TODO tokio?

                //- changes its state to Connect.
                self.to_state(State::Connect);
            }
            // optional:
            //(S::Active, E::DelayOpenTimerExpires) => { todo!() }
            //(S::Active, E::TcpConnectionValid) => { todo!() }
            //(S::Active, E::TcpCrInvalid) => { todo!() }
            (S::Active, E::TcpCrAcked | E::TcpConnectionConfirmed) => {
                let delayopen_implemented = false;

                if delayopen_implemented {
                    //If the DelayOpen attribute is set to TRUE, the local
                    //system:
                    todo!()
                    //  - stops the ConnectRetryTimer and sets the
                    //  ConnectRetryTimer to zero,
                    //  - sets the DelayOpenTimer to the initial value
                    //    (DelayOpenTime), and
                    //  - stays in the Active state.
                } else {
                    //If the DelayOpen attribute is set to FALSE, the local
                    //system:
                    //  - sets the ConnectRetryTimer to zero,
                    self.start_connect_retry_timer();

                    //  - completes the BGP initialization,
                    //  TODO something?

                    //  - sends the OPEN message to its peer,
                    //  TODO tokio

                    //  - sets its HoldTimer to a large value (sugg: 4min), 
                    //  TODO

                    //  - changes its state to OpenSent.
                    self.to_state(State::OpenSent);
                }
            }
            (S::Active, E::TcpConnectionFails) => {
                //- restarts the ConnectRetryTimer (with the initial value),
                self.start_connect_retry_timer();

                //- stops and clears the DelayOpenTimer (sets the value to
                // zero),
                // TODO once DelayOpenTimer is implemented

                //- releases all BGP resource,
                // TODO something?

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- optionally performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::Active, E::BgpOpenWithDelayOpenTimerRunning) => { todo!() }

            (S::Active, E::BgpHeaderErr | E::BgpOpenMsgErr) => { 
                //- (optionally) sends a NOTIFICATION message with the
                //appropriate error code if the SendNOTIFICATIONwithoutOPEN
                //attribute is set to TRUE,
                // TODO

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();
                
                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            (S::Active, E::NotifMsgVerErr) => {
                let delayopen_implemented_and_running = false;
                if delayopen_implemented_and_running {
                    // If the DelayOpenTimer is running, the local system:
                    //- stops the ConnectRetryTimer (if running) and sets the
                    //  ConnectRetryTimer to zero,
                    self.stop_connect_retry_timer();

                    //- stops and resets the DelayOpenTimer (sets to zero),
                    // TODO once DelayOpenTimer is implemented
                    
                    //- releases all BGP resources,
                    // TODO something?
                    
                    //- drops the TCP connection, and
                    // TODO tokio
                    
                    //- changes its state to Idle.
                    self.to_state(State::Idle);
                } else {
                    //If the DelayOpenTimer is not running, the local system:
                    //  - sets the ConnectRetryTimer to zero,
                    self.start_connect_retry_timer();

                    //  - releases all BGP resources,
                    //  TODO something?

                    //  - drops the TCP connection,
                    //  TODO tokio

                    //  - increments the ConnectRetryCounter by 1,
                    self.increase_connect_retry_counter();

                    //  - (optionally) performs peer oscillation damping if
                    //  the DampPeerOscillations attribute is set to TRUE, and
                    // TODO once DampPeerOscillations is implemented

                    //  - changes its state to Idle.
                    self.to_state(State::Idle);
                }
            }

            (S::Active, 
                //E::AutomaticStop |
                E::HoldTimerExpires |
                E::KeepaliveTimerExpires |
                //E::IdleHoldTimerExpires |
                E::BgpOpen |
                //E::OpenCollisionDump |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
                ) => {
                    //- sets the ConnectRetryTimer to zero,
                    self.start_connect_retry_timer();

                    //- releases all BGP resources,
                    // TODO something?

                    //- drops the TCP connection,
                    // TODO tokio

                    //- increments the ConnectRetryCounter by one,
                    self.increase_connect_retry_counter();

                    //- (optionally) performs peer oscillation damping if the
                    //  DampPeerOscillations attribute is set to TRUE, and
                    //  TODO once DampPeerOscillations is implemented

                    //- changes its state to Idle.
                    self.to_state(State::Idle);
            }


            //--- OpenSent ---------------------------------------------------

            (S::OpenSent, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state OpenSent", event)
            }
            (S::OpenSent, E::ManualStop) => {
                //- sends the NOTIFICATION with a Cease,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- sets the ConnectRetryCounter to zero, and
                self.reset_connect_retry_counter();

                //- changes its state to Idle.
                self.to_state(State::Idle);

            }
            // optional: 
            //S::OpenSent, E::AutomaticStop) => { todo!() }
            (S::OpenSent, E::HoldTimerExpires) => {
                //- sends a NOTIFICATION message with the error code Hold
                //Timer Expired,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenSent,
             //E::TcpConnectionValid | // optional
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                todo!()
                  //If a TcpConnection_Valid (Event 14), Tcp_CR_Acked (Event
                  //16), or a TcpConnectionConfirmed event (Event 17) is
                  //received, a second TCP connection may be in progress.
                  //This second TCP connection is tracked per Connection
                  //Collision processing (Section 6.8) until an OPEN message
                  //is received.
            }

            // optional:
            //(S::OpenSent, E::TcpCrInvalid) => { 
            //    info!("ignored {:?} in state OpenSent", event)
            //}

            (S::OpenSent, E::TcpConnectionFails) => {
                //- closes the BGP connection,
                // TODO tokio

                //- restarts the ConnectRetryTimer,
                self.start_connect_retry_timer();

                //- continues to listen for a connection that may be initiated
                //  by the remote BGP peer, and
                //  TODO tokio

                //- changes its state to Active.
                self.to_state(State::Active);
            }
            (S::OpenSent, E::BgpOpen) => {
                //- resets the DelayOpenTimer to zero,
                // TODO once DelayOpenTimer is implemented

                //- sets the BGP ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- sends a KEEPALIVE message, and
                // TODO tokio
                //self.handler.send_raw(KeepaliveBuilder::new_vec().finish());
                self.send_keepalive();

                //- sets a KeepaliveTimer:
                // If the negotiated hold time value is zero, then the
                // HoldTimer and KeepaliveTimer are not started.  If the value
                // of the Autonomous System field is the same as the local
                // Autonomous System number, then the connection is an
                // "internal" connection; otherwise, it is an "external"
                // connection.  (This will impact UPDATE processing as
                // described below.)
                // TODO

                //- sets the HoldTimer according to the negotiated value (see
                //  Section 4.2),
                //  TODO

                //- changes its state to OpenConfirm.
                self.to_state(State::OpenConfirm);
            }
            (S::OpenSent, E::BgpHeaderErr | E::BgpOpenMsgErr) => {
                //- sends a NOTIFICATION message with the appropriate error
                //code,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::OpenSent, E::OpenCollisionDump) => { todo!() }
            (S::OpenSent, E::NotifMsgVerErr) => {
                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection, and
                // TODO tokio

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenSent, 
                E::ConnectRetryTimerExpires |
                E::KeepaliveTimerExpires |
                //E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::NotifMsg |
                E::KeepaliveMsg |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- sends the NOTIFICATION with the Error Code Finite State
                //Machine Error,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection,
                // TODO tokio?

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            
            //--- OpenConfirm ------------------------------------------------


            (S::OpenConfirm, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state OpenConfirm", event)
            }
            (S::OpenConfirm, E::ManualStop) => {
                //- sends the NOTIFICATION message with a Cease,
                // TODO tokio

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- sets the ConnectRetryCounter to zero,
                self.reset_connect_retry_counter();

                //- sets the ConnectRetryTimer to zero, and
                self.start_connect_retry_timer();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional: 
            //(S::OpenConfirm, E::AutomaticStop) => { todo!() }
           
            (S::OpenConfirm, E::HoldTimerExpires) => {
                //- sends the NOTIFICATION message with the Error Code Hold
                //Timer Expired,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::KeepaliveTimerExpires) => {
                //- sends a KEEPALIVE message,
                // TODO tokio

                //- restarts the KeepaliveTimer, and
                // TODO

                //- remains in the OpenConfirmed state.
                // noop
            }

            (S::OpenConfirm,
             //E::TcpConnectionValid | // optional
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                todo!()
                // TODO: track second connection
            }

            // optional:
            //(S::OpenConfirm, E::TcpCrInvalid) => { 
            //    info!("ignored {:?} in state OpenConfirm", event)
            //}

            (S::OpenConfirm, E::TcpConnectionFails | E::NotifMsg ) => {
                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::NotifMsgVerErr) => {
                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection, and
                //TODO tokio

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::BgpOpen) => {
                // If the local system receives a valid OPEN message (BGPOpen
                // (Event 19)), the collision detect function is processed per
                //    Section 6.8.  If this connection is to be dropped due to
                //    connection collision, the local system:

                //- sends a NOTIFICATION with a Cease,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection (send TCP FIN),
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::OpenConfirm, E::BgpHeaderErr | E::BgpOpenMsgErr) => {
                //- sends a NOTIFICATION message with the appropriate error
                //code,
                // TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::OpenConfirm, E::OpenCollisionDump) => { todo!() }
            (S::OpenConfirm, E::KeepaliveMsg) => {
                //- restarts the HoldTimer and
                // TODO

                //- changes its state to Established.
                self.to_state(State::Established);
            }
            (S::OpenConfirm, 
                E::ConnectRetryTimerExpires |
                //E::DelayOpenTimerExpires |
                //E::IdleHoldTimerExpires |
                //E::BgpOpenWithDelayOpenTimerRunning |
                E::UpdateMsg |
                E::UpdateMsgErr
            ) => {
                //- sends a NOTIFICATION with a code of Finite State Machine
                //  Error,
                //  TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                //TODO something?

                //- drops the TCP connection,
                //TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            //--- Established ------------------------------------------------

            (S::Established, E::ManualStart /* | events 3-7 */ ) => {
                info!("ignored {:?} in state Established", event)
            }
            (S::Established, E::ManualStop) => {
                //- sends the NOTIFICATION message with a Cease,
                //TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- deletes all routes associated with this connection,
                //TODO manage store

                //- releases BGP resources,
                //TODO something?

                //- drops the TCP connection,
                //TODO tokio

                //- sets the ConnectRetryCounter to zero, and
                self.reset_connect_retry_counter();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            // optional:
            //(S::Established, E::AutomaticStop) => { todo!() }

            (S::Established, E::HoldTimerExpires) => {

                //- sends a NOTIFICATION message with the Error Code Hold Timer
                //  Expired,
                //  TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO store

                //- drops the TCP connection,
                //TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
            (S::Established, E::KeepaliveTimerExpires) => {
                //- sends a KEEPALIVE message, and
                // TODO tokio

                //- restarts its KeepaliveTimer, unless the negotiated HoldTime
                //  value is zero.
                //  TODO
            }
            // optional:
            // (S::Established, E::TcpConnectionValid) => { todo!() }
            // (S::Established, E::TcpCrInvalid) => { info!("ignored etc") }

            (S::Established,
             E::TcpCrAcked | E::TcpConnectionConfirmed ) => {
                todo!()
                // In response to an indication that the TCP connection is
                // successfully established (Event 16 or Event 17), the second
                // connection SHALL be tracked until it sends an OPEN message.
            }
            (S::Established, E::BgpOpen) => {
                todo!()
                // once CollisionDetectEstablishedState is implemented, things
                // need to happen here
            }
            // optional:
            //(S::Established, E::OpenCollisionDump) => { todo!() }
            (S::Established,
             E::NotifMsgVerErr | E::NotifMsg | E::TcpConnectionFails) => {

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- deletes all routes associated with this connection,
                // TODO store

                //- releases all the BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }

            (S::Established, E::KeepaliveMsg) => {
                //- restarts its HoldTimer, if the negotiated HoldTime value is
                //  non//-zero, and
                // TODO

                //- remains in the Established state.
                //self.to_state(State::Established);
            }
            (S::Established, E::UpdateMsg) => {
                //- processes the message,
                // TODO

                //- restarts its HoldTimer, if the negotiated HoldTime value is
                //  non//-zero, and
                //  TODO

                //- remains in the Established state.
                // noop
            }
            (S::Established, E::UpdateMsgErr) => {
                //- sends a NOTIFICATION message with an Update error,
                //TODO tokio

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- deletes all routes associated with this connection,
                // TODO store

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                // DampPeerOscillations attribute is set to TRUE, and
                // TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }


            (S::Established, 
                E::ConnectRetryTimerExpires |
                E::BgpHeaderErr |
                E::BgpOpenMsgErr
            ) => {
                //- sends a NOTIFICATION message with the Error Code Finite State
                //  Machine Error,
                // TODO tokio

                //- deletes all routes associated with this connection,
                // TODO store

                //- sets the ConnectRetryTimer to zero,
                self.start_connect_retry_timer();

                //- releases all BGP resources,
                // TODO something?

                //- drops the TCP connection,
                // TODO tokio

                //- increments the ConnectRetryCounter by 1,
                self.increase_connect_retry_counter();

                //- (optionally) performs peer oscillation damping if the
                //  DampPeerOscillations attribute is set to TRUE, and
                //  TODO once DampPeerOscillations is implemented

                //- changes its state to Idle.
                self.to_state(State::Idle);
            }
        }
    }
}

//=========== Error Types ====================================================

use std::fmt;
#[derive(Debug)]
pub struct ConnectionError;
impl std::error::Error for ConnectionError { }
impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection failed")
    }
}
impl From<std::io::Error> for ConnectionError {
    fn from(_: std::io::Error) -> Self {
        ConnectionError
    }
}

//--- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    fn test_session() -> Session<DefaultHandler> {
        Session::new(Asn::from_u32(12345), [192, 0, 2, 1])
    }

    //--- Idle ---------------------------------------------------------------
    #[test]
    fn idle_to_connect() {
        let mut s = test_session();
        assert_eq!(s.state(), State::Idle);
        let t1 = s.session().connect_retry_last_tick;
        assert!(t1.is_none());

        s.handle_event(Event::ManualStart);
        assert_eq!(s.state(), State::Connect);
        
        let t2 = s.session().connect_retry_last_tick;
        assert!(t2.is_some());
    }

    #[test]
    fn idle_manualstop() {
        let mut s = Session::new();
        assert_eq!(s.state(), State::Idle);
        s.handle_event(Event::ManualStop);
        assert_eq!(s.state(), State::Idle);
    }

    //--- Connect ------------------------------------------------------------
    #[test]
    fn connect_manualstop() {
        let mut s = Session::new();
        s.handle_event(Event::ManualStart);
        s.handle_event(Event::ManualStop);
        assert_eq!(s.state(), State::Idle);


    }

}
