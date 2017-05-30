use analysis::fixed_point::*;
use error::*;
use il;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Constraints {
    variable_constraints: BTreeMap<AnalysisLocation, il::Expression>,
    memory_constraints: BTreeMap<AnalysisLocation, (il::Expression, il::Expression)>
}


impl Constraints {
    pub fn new() -> Constraints {
        Constraints {
            variable_constraints: BTreeMap::new(),
            memory_constraints: BTreeMap::new()
        }
    }

    pub fn variable_constraints(&self) -> &BTreeMap<AnalysisLocation, il::Expression> {
        &self.variable_constraints
    }

    pub fn memory_constraints(&self)
    -> &BTreeMap<AnalysisLocation, (il::Expression, il::Expression)> {
        &self.memory_constraints
    }
}


pub struct ConstraintAnalysis<'c> {
    control_flow_graph: &'c il::ControlFlowGraph
}


impl<'c> ConstraintAnalysis<'c> {
    pub fn new(control_flow_graph: &'c il::ControlFlowGraph)
    -> ConstraintAnalysis<'c> {
        ConstraintAnalysis {
            control_flow_graph: control_flow_graph
        }
    }


    pub fn control_flow_graph(&self) -> &il::ControlFlowGraph {
        &self.control_flow_graph
    }


    pub fn compute(&self) -> Result<BTreeMap<AnalysisLocation, Constraints>> {
        fixed_point_backward(self, self.control_flow_graph)
    }
}


fn instruction_constraints(
    instruction: &il::Instruction,
    constraints: &mut Constraints
) {
    // This is a mapping of analysis locations where constraints originated to
    // the variables in those constraints. We can use the analysis location to
    // find this constraint later, as all constraints are uniquely identified
    // by the location of their origin.
    let conditions: BTreeSet<(AnalysisLocation, il::Variable)>
        = constraints.variable_constraints.iter()
            .fold(BTreeSet::new(), |mut set, c| {
                let al = c.0;
                let expr = c.1;
                for v in expr.collect_variables() {
                    set.insert((al.clone(), v.clone()));
                }
                set
            });

    // This is a set of variables in a condition.
    let condition_variables = conditions.iter()
                                        .map(|c| c.1.clone())
                                        .collect::<BTreeSet<il::Variable>>();

    // Constraints over memory that we need to add, transfering constraints from
    // the destination of a load to take affect over that memory location.
    let mut new_memory_constraints: Vec<(
        AnalysisLocation,
        il::Expression,
        il::Expression
    )> = Vec::new();
    // This replaces variables in a constrant expression with the variable being
    // assigned at this location.
    let mut replacements: BTreeMap<il::Expression, &il::Expression> = BTreeMap::new();
    // These are variable constraints which are no longer valid.
    let mut kill_set: BTreeSet<&AnalysisLocation> = BTreeSet::new();

    match *instruction.operation() {
        il::Operation::Assign{ref dst, ref src} => {
            if condition_variables.contains(dst) {
                replacements.insert(dst.clone().into(), src);
            }
        },
        il::Operation::Load{ref dst, ref address} => {
            for c in &conditions {
                if c.1 == *dst {
                    kill_set.insert(&c.0);
                    new_memory_constraints.push((
                        c.0.clone(),
                        address.clone(),
                        constraints.variable_constraints[&c.0].clone()
                    ));
                }
            }
        },
        _ => {}
    }

    // Remove any variable constraints that we killed.
    for kill in kill_set {
        constraints.variable_constraints.remove(&kill);
    }

    // Insert any new memory constraints we have
    for nmc in new_memory_constraints {
        constraints.memory_constraints.insert(nmc.0, (nmc.1, nmc.2));
    }

    for (al, constraint) in constraints.variable_constraints.iter_mut() {
        for expr_var in constraint.collect_variable_exprs_mut() {
            if let Some(replacement_expr) = replacements.get(expr_var) {
                *expr_var = (*replacement_expr).clone();
            }
        }
    }
}


impl<'c> FixedPointAnalysis<Constraints> for ConstraintAnalysis<'c> {

    fn trans (
        &self,
        analysis_location: &AnalysisLocation,
        constraints_in: &Option<Constraints>
    ) -> Result<Constraints> {

        let mut constraints_out = match *constraints_in {
            None => Constraints::new(),
            Some(ref constraints) => constraints.clone()
        };

        constraints_out.memory_constraints = BTreeMap::new();

        info!(
            "{} {}/{}",
            analysis_location,
            constraints_out.variable_constraints.len(),
            constraints_out.memory_constraints.len()
        );

        match *analysis_location {
            AnalysisLocation::Edge(ref el) => {
                if let Some(ref condition) = *el.find(self.control_flow_graph)?
                                            .condition() {
                    constraints_out = Constraints::new();
                    constraints_out.variable_constraints.insert(
                        analysis_location.clone(),
                        condition.clone()
                    );
                }
            }
            AnalysisLocation::Instruction(ref il) => {
                let instruction = il.find(self.control_flow_graph)?;
                instruction_constraints(instruction, &mut constraints_out);
            }
            AnalysisLocation::EmptyBlock(_) => {}
        }

        info!("constraints_out.len() = {}", constraints_out.memory_constraints.len());

        Ok(constraints_out)
    }


    fn join(&self, mut state0: Constraints, state1: &Constraints)
    -> Result<Constraints> {
        info!(
            "merging {}/{} and {}/{} states",
            state0.variable_constraints.len(),
            state0.memory_constraints.len(),
            state1.variable_constraints.len(),
            state1.memory_constraints.len()
        );
        for (al, constraint) in &state1.variable_constraints {
            state0.variable_constraints.insert(al.clone(), constraint.clone());
        }

        Ok(state0)
    }

}