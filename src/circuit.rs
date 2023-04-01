// for the unhandled Result values from write and writeln
#![allow(unused_must_use)]

use std::collections::HashMap;
use std::{fmt, str::FromStr};

use crate::utilities;

pub enum GateOp {
    Add,
    Mul,
}

impl fmt::Display for GateOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateOp::Add => write!(f, "+"),
            GateOp::Mul => write!(f, "×"),
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum Party {
    P1,
    P2,
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Party::P1 => write!(f, "P1"),
            Party::P2 => write!(f, "P2"),
        }
    }
}

#[derive(PartialEq)]
pub enum GateInput {
    Id(u32),
    InputParty(Party),
}

impl fmt::Display for GateInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateInput::Id(i) => write!(f, "{}", i),
            GateInput::InputParty(p) => write!(f, "{}", p),
        }
    }
}

impl FromStr for GateInput {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "p1" => Ok(GateInput::InputParty(Party::P1)),
            "p2" => Ok(GateInput::InputParty(Party::P2)),
            _ => match s.parse::<u32>() {
                Ok(n) => Ok(GateInput::Id(n)),
                Err(_) => Err(format!("Invalid gate input format: {s}")),
            },
        }
    }
}

pub enum Gate {
    GateWithoutC {
        id: u32,
        op: GateOp,
        i1: GateInput,
        i2: GateInput,
    },
    GateWithC {
        id: u32,
        op: GateOp,
        i1: GateInput,
        c: i32,
    },
}

impl fmt::Display for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Gate::GateWithoutC { id, op, i1, i2 } => {
                write!(f, "[{} | {} {} {})", id, i1, op, i2)
            }
            Gate::GateWithC { id, op, i1, c } => {
                write!(f, "[{} | {} {} C({}))", id, i1, op, c)
            }
        }
    }
}

impl FromStr for Gate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let terms: String = s.chars().filter(|c| !c.is_whitespace()).collect();

        if let [id, i1, op, opt] = terms.split(",").collect::<Vec<&str>>()[..] {
            let id: u32 = match id.parse() {
                Ok(n) => n,
                Err(_) => {
                    return Err(format!("Invalid id format: {id}"));
                }
            };

            let mut constant = false;

            let op: GateOp = match op.to_lowercase().as_str() {
                "add" => GateOp::Add,
                "addc" => {
                    constant = true;
                    GateOp::Add
                }
                "mul" => GateOp::Mul,
                "mulc" => {
                    constant = true;
                    GateOp::Mul
                }
                _ => {
                    return Err(format!("Invalid gate operation: {op}"));
                }
            };

            let i1: GateInput = i1.parse()?;

            if constant {
                let c: i32 = match opt.parse() {
                    Ok(n) => n,
                    Err(_) => {
                        return Err(format!("Invalid constant format: {opt}"));
                    }
                };

                return Ok(Gate::GateWithC { id, op, i1, c });
            } else {
                let i2: GateInput = opt.parse()?;

                return Ok(Gate::GateWithoutC { id, op, i1, i2 });
            }
        } else {
            return Err(format!(
                "Invalid number of gate parameters (should be 4): {s}"
            ));
        }
    }
}

impl Gate {
    fn get_id(&self) -> u32 {
        match self {
            Gate::GateWithoutC { id, .. } => *id,
            Gate::GateWithC { id, .. } => *id,
        }
    }
}

pub struct Circuit {
    gates: HashMap<u32, Gate>,
    outputs_p1: Vec<u32>,
    outputs_p2: Vec<u32>,
    topology: Vec<u32>,
    inputs_p1: (Vec<u32>, Vec<u32>),
    inputs_p2: (Vec<u32>, Vec<u32>),
}

impl fmt::Display for Circuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{");
        for (_, g) in &self.gates {
            writeln!(f, "    {g}")?;
        }

        writeln!(
            f,
            "    Outputs for P1: {}",
            self.outputs_p1
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
        writeln!(
            f,
            "    Outputs for P2: {}",
            self.outputs_p2
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
        write!(f, "}}");

        Ok(())
    }
}

impl FromStr for Circuit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut gates = HashMap::new();
        let mut inputs_p1_first = Vec::new();
        let mut inputs_p1_second = Vec::new();
        let mut inputs_p2_first = Vec::new();
        let mut inputs_p2_second = Vec::new();

        if let [gates_str, output1_str, output2_str] = s.split("&").collect::<Vec<&str>>()[..] {
            let outputs_p1 = utilities::str_u32_to_vec_u32(output1_str)?;
            let outputs_p2 = utilities::str_u32_to_vec_u32(output2_str)?;

            // processing gates
            for g_str in gates_str.trim().split("|") {
                if g_str.len() == 0 {
                    continue;
                } else {
                    let g: Gate = g_str.parse()?;
                    let id = g.get_id();

                    // adding to input list. it is necessary to separate the inputs into two vectors
                    // (one for the first wire, one for the second one) at the very least, because we
                    // allow gates to receive both inputs from the same party)
                    match &g {
                        Gate::GateWithoutC { i1, i2, .. } => {
                            match *i1 {
                                GateInput::InputParty(Party::P1) => inputs_p1_first.push(id),
                                GateInput::InputParty(Party::P2) => inputs_p2_first.push(id),
                                _ => (),
                            }
                            match *i2 {
                                GateInput::InputParty(Party::P1) => inputs_p1_second.push(id),
                                GateInput::InputParty(Party::P2) => inputs_p2_second.push(id),
                                _ => (),
                            }
                        }
                        Gate::GateWithC { i1, .. } => match *i1 {
                            GateInput::InputParty(Party::P1) => inputs_p1_first.push(id),
                            GateInput::InputParty(Party::P2) => inputs_p2_first.push(id),
                            _ => (),
                        },
                    }

                    gates.insert(id, g);
                }
            }

            inputs_p1_first.sort();
            inputs_p1_second.sort();
            inputs_p2_first.sort();
            inputs_p2_second.sort();

            // obtaining list of all outputs. ensuring order is essential for protocol synchronisation
            let mut outputs_all = outputs_p1.clone();
            outputs_all.extend(&outputs_p2);
            outputs_all.sort();
            outputs_all.dedup();

            let topology = compute_topology(&gates, &outputs_all)?;

            Ok(Circuit {
                gates,
                outputs_p1,
                outputs_p2,
                topology,
                inputs_p1: (inputs_p1_first, inputs_p1_second),
                inputs_p2: (inputs_p2_first, inputs_p2_second),
            })
        } else {
            Err("Invalid circuit input format, should be: <gates> & <outputs_to_P1> & <outputs_to_P2>".to_string())
        }
    }
}

impl Circuit {
    // vec is returned to guarantee order, which is crucial for synchronisation
    pub fn get_inputs_p1(&self) -> &(Vec<u32>, Vec<u32>) {
        &self.inputs_p1
    }

    pub fn get_inputs_p2(&self) -> &(Vec<u32>, Vec<u32>) {
        &self.inputs_p2
    }

    pub fn total_input_wires(&self) -> usize {
        self.inputs_p1.0.len()
            + self.inputs_p1.1.len()
            + self.inputs_p2.0.len()
            + self.inputs_p2.1.len()
    }

    pub fn get_outputs(&self, party: Party) -> &Vec<u32> {
        match party {
            Party::P1 => &self.outputs_p1,
            Party::P2 => &self.outputs_p2,
        }
    }

    pub fn get_gate(&self, id: &u32) -> Option<&Gate> {
        self.gates.get(id)
    }

    pub fn get_topology(&self) -> &[u32] {
        &self.topology
    }
}

fn compute_topology(gates: &HashMap<u32, Gate>, outputs: &Vec<u32>) -> Result<Vec<u32>, String> {
    let mut top = Vec::new();

    for o in outputs {
        top = simplify(top, compute_topology_internal(gates, o)?);
    }

    Ok(top)
}

fn compute_topology_internal(gates: &HashMap<u32, Gate>, target: &u32) -> Result<Vec<u32>, String> {
    let mut req = match gates.get(target) {
        None => {
            return Err(format!(
                "Invalid topology: necessary gate {target} not found in circuit"
            ))
        }
        // Gates with exactly two input gates
        Some(Gate::GateWithoutC {
            i1: GateInput::Id(id1),
            i2: GateInput::Id(id2),
            ..
        }) => {
            if id1 == target || id2 == target {
                return Err(format!("Gate {} cannot be an input to itself", target));
            } else if id1 == id2 {
                compute_topology_internal(gates, id1)?
            } else {
                simplify(
                    compute_topology_internal(gates, id1)?,
                    compute_topology_internal(gates, id2)?,
                )
            }
        }
        // Gates with exactly one input gate
        Some(Gate::GateWithoutC {
            i1: GateInput::Id(id),
            ..
        })
        | Some(Gate::GateWithoutC {
            i2: GateInput::Id(id),
            ..
        })
        | Some(Gate::GateWithC {
            i1: GateInput::Id(id),
            ..
        }) => {
            if id == target {
                return Err(format!("Gate {} cannot be an input to itself", target));
            } else {
                compute_topology_internal(gates, id)?
            }
        }
        // Gates with no gate inputs (party-constant or party-party)
        _ => vec![],
    };

    if req.contains(target) {
        return Err(format!(
            "Invalid topology: it contains a cycle involving gate {}",
            target
        ));
    }

    req.push(*target);

    Ok(req)
}

// concatenate two vectors, removing from the second one the elements which are already present in the first one
fn simplify(mut v1: Vec<u32>, v2: Vec<u32>) -> Vec<u32> {
    for e in v2.into_iter() {
        if !v1.contains(&e) {
            v1.push(e);
        }
    }
    v1
}
