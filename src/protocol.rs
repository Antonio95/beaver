// for the unhandled Result values from send: should not occur by protocol design
#![allow(unused_must_use)]

use std::{
    collections::HashMap,
    fmt::Display,
    fs,
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use crate::sharing::*;
use crate::utilities;
use crate::{circuit::*, utilities::subtract_without_overflow};

enum Msg<T: Sharing> {
    Value(u32),
    Singleton(T),
    Triple(BeaverSharing<T>),
    Abort,
}

struct Dealer<T: Sharing> {
    circuit: Circuit,
    q: u32,
    tx_d_p1: Sender<Msg<T>>,
    tx_d_p2: Sender<Msg<T>>,
    log_path: String,
}

// a value in [0, 1] indicating how likely a corrupt party is to tamper with each opening it sends
const CORRUPTION_DEGREE: f32 = 0.2;

impl<T: Sharing> Dealer<T> {
    fn run(&self) -> Result<(), String> {
        let rng = &mut ChaCha20Rng::from_entropy();

        let o = &mut String::new();

        o.push_str("**** Distribution of key sharings\n");

        // distributing key sharings (not of type T: the former are always unauthenticated)
        let k1 = utilities::safe_gen_mod(rng, self.q);
        let k2 = utilities::safe_gen_mod(rng, self.q);
        let (sk11, sk12) = UnauthSharing::share(k1, 0, 0, rng, self.q);
        let (sk21, sk22) = UnauthSharing::share(k2, 0, 0, rng, self.q);

        self.tx_d_p1.send(Msg::Value(sk11.value()));
        log(o, false, "P1", "sharing of k1", &sk11);
        self.tx_d_p1.send(Msg::Value(sk21.value()));
        log(o, false, "P2", "sharing of k1", &sk12);
        self.tx_d_p2.send(Msg::Value(sk12.value()));
        log(o, false, "P1", "sharing of k2", &sk21);
        self.tx_d_p2.send(Msg::Value(sk22.value()));
        log(o, false, "P2", "sharing of k2", &sk22);

        o.push_str("\n**** Distribution of singleton sharings for inputs\n");
        // distributing sharings for input wires
        for _ in 0..self.circuit.total_input_wires() {
            let (s1, s2) = T::share(utilities::safe_gen_mod(rng, self.q), k1, k2, rng, self.q);
            self.tx_d_p1
                .send(Msg::Singleton(log(o, false, "P1", "singleton sharing", s1)));
            self.tx_d_p2
                .send(Msg::Singleton(log(o, false, "P2", "singleton sharing", s2)));
        }

        o.push_str("\n**** Distribution of triple sharings for multiplication gates\n");
        // need to run over the topology (rather than the hashmap of gates) to ensure order
        for id in self.circuit.get_topology() {
            // always gets a valid gate by construction
            match self.circuit.get_gate(id).unwrap() {
                Gate::GateWithoutC {
                    op: GateOp::Mul, ..
                } => {
                    let (t1, t2) = T::beaver_share(k1, k2, self.q, rng);
                    self.tx_d_p1
                        .send(Msg::Triple(log(o, false, "P1", "triple sharing", t1)));
                    self.tx_d_p2
                        .send(Msg::Triple(log(o, false, "P2", "triple sharing", t2)));
                }
                _ => (),
            }
        }

        o.push_str("\nEnded successfully");

        if let Err(e) = fs::write(&self.log_path, o) {
            return Err(format!(
                "Dealer failed to write execution log: {}",
                e.to_string()
            ));
        }

        // TODO keeping the dealer honest

        Ok(())
    }
}

struct ProtocolParty<T: Sharing> {
    identity: Party,
    circuit: Circuit,
    q: u32,
    inputs_first: Vec<u32>,
    inputs_second: Vec<u32>,
    corrupt: bool,
    rx_d_me: Receiver<Msg<T>>,
    rx_other_me: Receiver<Msg<T>>,
    tx_me_other: Sender<Msg<T>>,
    log_path: String,
    key: u32,
    s_k1: u32,
    s_k2: u32,
}

impl<T: Sharing> ProtocolParty<T> {
    fn run(&mut self) -> Result<(), String> {
        let o = &mut String::new();

        // distributing key sharings
        o.push_str("**** Distribution of key sharings\n");
        self.s_k1 = match self.rx_d_me.recv() {
            Ok(Msg::Value(v)) => log(o, true, "dealer", "sharing of k1", v),
            _ => {
                return Err(self.abort(
                    o,
                    "Error during distribution of key sharings: Expected sharing of k1",
                ))
            }
        };

        self.s_k2 = match self.rx_d_me.recv() {
            Ok(Msg::Value(v)) => log(o, true, "dealer", "sharing of k2", v),
            _ => {
                return Err(self.abort(
                    o,
                    "Error during distribution of key sharings: Expected sharing of k2",
                ))
            }
        };

        let mut singletons = Vec::new();

        // distributing sharings for input wires
        o.push_str("\n**** Distribution of singleton sharings for inputs\n");

        for _ in 0..self.circuit.total_input_wires() {
            match self.rx_d_me.recv() {
                Ok(Msg::Singleton(s)) => singletons.push(log(o, true, "dealer", "singleton sharing", s)),
                _ => return Err(self.abort(o, "Error during distribution of input and key-opening sharings: Expected singleton sharing")),
            };
        }

        o.push_str("\n**** Distribution of triple sharings for multiplication gates\n");

        let topology = self.circuit.get_topology();
        let mut triples = Vec::new();

        // need to run over the topology (rather than the hashmap of gates) to guarantee the same order across dealer and parties
        for id in topology {
            // always gets a valid gate by construction
            match self.circuit.get_gate(id).unwrap() {
                Gate::GateWithoutC {
                    op: GateOp::Mul, ..
                } => {
                    match self.rx_d_me.recv() {
                        Ok(Msg::Triple(t)) => {
                            triples.push(log(o, true, "dealer", "triple sharing", t))
                        }
                        _ => return Err(self.abort(
                            o,
                            "Error during distribution of Beaver sharings: Expected triple sharing",
                        )),
                    };
                }
                _ => (),
            }
        }

        // opening key sharings
        o.push_str("\n**** Opening of key sharings\n");
        if self.identity == Party::P1 {
            let k12 = match self.rx_other_me.recv() {
                Ok(Msg::Value(v)) => log(o, true, "other party", "opening of k1", v),
                _ => return Err(self.abort(o, "Error during key opening: Expected opening of k1")),
            };
            self.key = self.s_k1 + k12;
            self.tx_me_other.send(Msg::Value(log(
                o,
                false,
                "other party",
                "opening of k2",
                self.s_k2,
            )));
        } else {
            self.tx_me_other.send(Msg::Value(log(
                o,
                false,
                "other party",
                "opening of k1",
                self.s_k1,
            )));
            let k21 = match self.rx_other_me.recv() {
                Ok(Msg::Value(v)) => log(o, true, "other party", "opening of k2", v),
                _ => return Err(self.abort(o, "Error during key opening: Expected opening of k2")),
            };
            self.key = self.s_k2 + k21;
        }

        // input processing
        o.push_str("\n**** Processing input wires\n");

        let (i_p1_first, i_p1_second) = self.circuit.get_inputs_p1();
        let (i_p2_first, i_p2_second) = self.circuit.get_inputs_p2();

        let i_sharings_p1_first =
            self.process_inputs(o, i_p1_first, &mut singletons, Party::P1, true)?;
        let i_sharings_p1_second =
            self.process_inputs(o, i_p1_second, &mut singletons, Party::P1, false)?;
        let i_sharings_p2_first =
            self.process_inputs(o, i_p2_first, &mut singletons, Party::P2, true)?;
        let i_sharings_p2_second =
            self.process_inputs(o, i_p2_second, &mut singletons, Party::P2, false)?;

        // processing gates
        o.push_str("\n**** Processing gates\n");

        let mut inner_wires = HashMap::new();

        for id in self.circuit.get_topology() {
            let g = self.circuit.get_gate(id).unwrap();

            match g {
                Gate::GateWithoutC { op, i1, i2, .. } => {
                    let v1 = match i1 {
                        // these unwraps cannot fail by the order of the topology and input processing
                        GateInput::Id(s_id) => inner_wires.get(s_id).unwrap(),
                        GateInput::InputParty(Party::P1) => i_sharings_p1_first.get(id).unwrap(),
                        GateInput::InputParty(Party::P2) => i_sharings_p2_first.get(id).unwrap(),
                    };
                    let v2 = match i2 {
                        GateInput::Id(s_id) => inner_wires.get(s_id).unwrap(),
                        GateInput::InputParty(Party::P1) => i_sharings_p1_second.get(id).unwrap(),
                        GateInput::InputParty(Party::P2) => i_sharings_p2_second.get(id).unwrap(),
                    };

                    inner_wires.insert(
                        *id,
                        match op {
                            GateOp::Add => self.process_gate_add(v1, v2),
                            GateOp::Mul => self.process_gate_mul(o, v1, v2, triples.pop().unwrap())?,
                        },
                    );
                }
                Gate::GateWithC { op, i1, c, .. } => {
                    let v1 = match i1 {
                        GateInput::Id(s_id) => inner_wires.get(s_id).unwrap(),
                        GateInput::InputParty(Party::P1) => i_sharings_p1_first.get(id).unwrap(),
                        GateInput::InputParty(Party::P2) => i_sharings_p2_first.get(id).unwrap(),
                    };

                    let c = utilities::modulo(*c, self.q);

                    inner_wires.insert(
                        *id,
                        match op {
                            GateOp::Add => self.process_gate_addc(v1, c),
                            GateOp::Mul => self.process_gate_mulc(v1, c),
                        },
                    );
                }
            }
        }

        // processing outputs
        o.push_str("\n**** Processing outputs\n");

        let mut output_wires = HashMap::new();

        for id in self.circuit.get_outputs(Party::P1) {
            match self.identity {
                Party::P1 => {
                    output_wires.insert(id, self.receive_opening(o, inner_wires.get(id).unwrap())?);
                }
                Party::P2 => {
                    self.send_opening(o, inner_wires.get(id).unwrap());
                }
            };
        }

        for id in self.circuit.get_outputs(Party::P2) {
            match self.identity {
                Party::P2 => {
                    output_wires.insert(id, self.receive_opening(o, inner_wires.get(id).unwrap())?);
                }
                Party::P1 => {
                    self.send_opening(o, inner_wires.get(id).unwrap());
                }
            };
        }

        o.push('\n');

        for (id, v) in output_wires {
            o.push_str(&format!("Output of gate {}: {}\n", id, v));
        }

        o.push_str("\nEnded successfully");

        if let Err(e) = fs::write(&self.log_path, o) {
            return Err(format!(
                "{} failed to write execution log: {}",
                self.identity,
                e.to_string()
            ));
        }

        Ok(())
    }
    fn abort(&self, output: &mut String, msg: &str) -> String {
        self.tx_me_other.send(Msg::Abort);

        let abort_msg = format!("{}. Aborting.", msg);
        output.push_str(&abort_msg);

        if let Err(e) = fs::write(&self.log_path, output) {
            return format!(
                "{} failed to write execution log: {}",
                self.identity,
                e.to_string()
            );
        }

        abort_msg
    }
    fn send_opening(&self, output: &mut String, s: &T) {
        if self.corrupt && rand::random::<f32>() <= CORRUPTION_DEGREE {
            // not part of the protocol! only here to simulate a  corrupt party
            println!("(Corrupt {} tampering with sharing)", self.identity);
            let s_t = s.tweaked();
            self.tx_me_other.send(Msg::Singleton(log(
                output,
                false,
                "other party",
                "*tampered-with* opened sharing",
                s_t.opened(self.other_party()),
            )));
        } else {
            self.tx_me_other.send(Msg::Singleton(log(
                output,
                false,
                "other party",
                "opened sharing",
                s.opened(self.other_party()),
            )));
        }
    }
    fn receive_opening(&self, output: &mut String, own_s: &T) -> Result<u32, String> {
        match self.rx_other_me.recv() {
            Ok(Msg::Singleton(s)) => {
                let new_s = T::add(
                    own_s,
                    &log(output, true, "other party", "opened sharing", s),
                    self.q,
                );
                if T::authenticate(&new_s, self.key, self.q, self.identity) {
                    Ok(new_s.value())
                } else {
                    Err(self.abort(
                        output,
                        &format!("Authentication failed for sharing {new_s}"),
                    ))
                }
            }
            _ => Err(self.abort(
                output,
                "Error during opening of sharing: Expected opened sharing",
            )),
        }
    }
    fn process_inputs(
        &self,
        output: &mut String,
        ids: &Vec<u32>,
        singletons: &mut Vec<T>,
        source: Party,
        first: bool,
    ) -> Result<HashMap<u32, T>, String> {
        let mut sharing_hash = HashMap::new();

        if source == self.identity {
            let inputs = if first {&self.inputs_first} else {&self.inputs_second};

            for (id, v) in ids.iter().zip(inputs.iter()) {
                let a = singletons.pop().unwrap(); // cannot fail due to to sharing count
                let a_open = self.receive_opening(output, &a)?;
                let d = subtract_without_overflow(*v, a_open, self.q);

                self.tx_me_other.send(Msg::Value(log(
                    output,
                    false,
                    "other party",
                    "delta for input processing",
                    d,
                )));

                sharing_hash.insert(
                    *id,
                    T::addc(&a, d, self.s_k1, self.s_k2, self.q, self.identity),
                );
            }
        } else {
            for id in ids {
                let a = singletons.pop().unwrap();
                self.send_opening(output, &a);

                let d = match self.rx_other_me.recv() {
                    Ok(Msg::Value(v)) => log(output, true, "other party", "delta for input processing", v),
                    _ => return Err(self.abort(output, "Error during distribution of key sharings: expected delta for input processing")),
                };

                sharing_hash.insert(
                    *id,
                    T::addc(&a, d, self.s_k1, self.s_k2, self.q, self.identity),
                );
            }
        }

        Ok(sharing_hash)
    }
    fn process_gate_add(&self, s1: &T, s2: &T) -> T {
        T::add(s1, s2, self.q)
    }
    fn process_gate_mul(
        &self,
        output: &mut String,
        s1: &T,
        s2: &T,
        BeaverSharing(a, b, c): BeaverSharing<T>,
    ) -> Result<T, String> {
        let u = T::subtract(s1, &a, self.q);
        let v = T::subtract(s2, &b, self.q);

        self.send_opening(output, &u);
        self.send_opening(output, &v);

        let u_open = self.receive_opening(output, &u)?;
        let v_open = self.receive_opening(output, &v)?;

        Ok(T::addc(
            &T::add(
                &T::mulc(&b, u_open, self.q),
                &T::add(&T::mulc(&a, v_open, self.q), &c, self.q),
                self.q,
            ),
            u_open * v_open,
            self.s_k1,
            self.s_k2,
            self.q,
            self.identity,
        ))
    }
    fn process_gate_addc(&self, s: &T, c: u32) -> T {
        T::addc(s, c, self.s_k1, self.s_k2, self.q, self.identity)
    }
    fn process_gate_mulc(&self, s: &T, c: u32) -> T {
        T::mulc(s, c, self.q)
    }
    fn other_party(&self) -> Party {
        match self.identity {
            Party::P1 => Party::P2,
            Party::P2 => Party::P1,
        }
    }
}

pub fn run_beaver_protocol(
    circuit_encoding: &str,
    q: u32,
    inputs_p1_first: Vec<u32>,
    inputs_p1_second: Vec<u32>,
    inputs_p2_first: Vec<u32>,
    inputs_p2_second: Vec<u32>,
    authenticated: bool,
    corrupt: bool,
    output_path: &str,
) -> Result<(), String> {
    if authenticated {
        run_beaver_protocol_internal::<AuthSharing>(
            circuit_encoding,
            q,
            inputs_p1_first,
            inputs_p1_second,
            inputs_p2_first,
            inputs_p2_second,
            corrupt,
            output_path,
        )
    } else {
        run_beaver_protocol_internal::<UnauthSharing>(
            circuit_encoding,
            q,
            inputs_p1_first,
            inputs_p1_second,
            inputs_p2_first,
            inputs_p2_second,
            corrupt,
            output_path,
        )
    }
}

fn run_beaver_protocol_internal<T: Sharing + 'static>(
    circuit_encoding: &str,
    q: u32,
    inputs_p1_first: Vec<u32>,
    inputs_p1_second: Vec<u32>,
    inputs_p2_first: Vec<u32>,
    inputs_p2_second: Vec<u32>,
    corrupt: bool,
    output_path: &str,
) -> Result<(), String> {
    // TODO prime verification

    let c1: Circuit = circuit_encoding.parse()?;
    // the next two calls cannot fail if this line is reached
    // the circuit is computed separately by each party to mimic execution in independent machines
    let c2: Circuit = circuit_encoding.parse().unwrap();
    let c3: Circuit = circuit_encoding.parse().unwrap();

    let (tx_d_p1, rx_d_p1) = mpsc::channel::<Msg<T>>();
    let (tx_d_p2, rx_d_p2) = mpsc::channel::<Msg<T>>();
    let (tx_p1_p2, rx_p1_p2) = mpsc::channel::<Msg<T>>();
    let (tx_p2_p1, rx_p2_p1) = mpsc::channel::<Msg<T>>();

    let dealer = Dealer {
        circuit: c1,
        q,
        tx_d_p1,
        tx_d_p2,
        log_path: format!("{}_dealer.txt", output_path),
    };

    // if corrupt, randomly choose a party to be so; otherwise, no party is so
    let p1_corrupt = corrupt && rand::random::<bool>();
    let p2_corrupt = corrupt && !p1_corrupt;

    let (input_ids_p1_first, input_ids_p1_second) = c2.get_inputs_p1();
    if input_ids_p1_first.len() != inputs_p1_first.len() || input_ids_p1_second.len() != inputs_p1_second.len() {
        return Err(String::from("Error: number of input values provided by P1 does not match the circuit's needs"));
    }

    let (input_ids_p2_first, input_ids_p2_second) = c3.get_inputs_p2();
    if input_ids_p2_first.len() != inputs_p2_first.len() || input_ids_p2_second.len() != inputs_p2_second.len() {
        return Err(String::from("Error: number of input values provided by P2 does not match the circuit's needs"));
    }

    let mut party1 = ProtocolParty {
        identity: Party::P1,
        q,
        circuit: c2,
        inputs_first: inputs_p1_first,
        inputs_second: inputs_p1_second,
        corrupt: p1_corrupt,
        rx_d_me: rx_d_p1,
        rx_other_me: rx_p2_p1,
        tx_me_other: tx_p1_p2,
        log_path: format!("{}_p1.txt", output_path),
        key: 0,
        s_k1: 0,
        s_k2: 0,
    };

    let mut party2 = ProtocolParty {
        identity: Party::P2,
        circuit: c3,
        q,
        inputs_first: inputs_p2_first,
        inputs_second: inputs_p2_second,
        corrupt: p2_corrupt,
        rx_d_me: rx_d_p2,
        rx_other_me: rx_p1_p2,
        tx_me_other: tx_p2_p1,
        log_path: format!("{}_p2.txt", output_path),
        key: 0,
        s_k1: 0,
        s_k2: 0,
    };

    let thread_dealer = thread::spawn(move || dealer.run());

    let thread_p1 = thread::spawn(move || party1.run());

    let thread_p2 = thread::spawn(move || party2.run());

    let mut err_str = String::new();

    if let Err(e) = thread_dealer.join().unwrap() {
        err_str.push_str(&format!("Dealer: {e}\n"));
    }
    if let Err(e) = thread_p1.join().unwrap() {
        err_str.push_str(&format!("P1: {e}\n"));
    }
    if let Err(e) = thread_p2.join().unwrap() {
        err_str.push_str(&format!("P2: {e}\n"));
    }

    err_str.pop();

    if err_str.is_empty() {
        Ok(())
    } else {
        Err(err_str)
    }
}

fn log<T: Display>(output: &mut String, receive: bool, other: &str, desc: &str, value: T) -> T {
    output.push_str(&format!(
        "{} {other} {desc}: {value}\n",
        if receive { "Received from" } else { "Sent to" }
    ));
    value
}
