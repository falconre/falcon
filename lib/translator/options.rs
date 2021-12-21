use crate::il;
use std::default;

/// An edge that will not be detected by Falcon's translator, but should exist.
///
/// This is used for re-lifting functions after Raptor has performed its jump
/// table analysis.
#[derive(Clone, Debug)]
pub struct ManualEdge {
    head_address: u64,
    tail_address: u64,
    condition: Option<il::Expression>,
}

impl ManualEdge {
    /// Create a new manual edge
    ///
    /// * `head_address` - The address of the instruction where this manual edge
    /// should begin.
    /// * `tail_address` - The address of the block this edge should point to.
    /// * `condition` - An optional condition which guards this edge.
    ///
    /// If there is no block at `tail_address`, this will cause the translator
    /// to lift a block at the `tail_address`.
    pub fn new(
        head_address: u64,
        tail_address: u64,
        condition: Option<il::Expression>,
    ) -> ManualEdge {
        ManualEdge {
            head_address,
            tail_address,
            condition,
        }
    }

    /// Get the address of the instruction where this manual edge begins
    pub fn head_address(&self) -> u64 {
        self.head_address
    }

    /// Get the address of the block where this manual edge ends.
    pub fn tail_address(&self) -> u64 {
        self.tail_address
    }

    /// If this condition is guarded by a condition, get the condition
    pub fn condition(&self) -> Option<&il::Expression> {
        self.condition.as_ref()
    }
}

/// Various options that can be passed to the translator. Options will change
/// the behavior of the translator.
#[derive(Clone, Debug, Default)]
pub struct Options {
    manual_edges: Vec<ManualEdge>,
    unsupported_are_intrinsics: bool,
}

impl Options {
    /// Create a new set of Options with the default settings.
    pub fn new() -> Options {
        Options::default()
    }

    /// Set the value of the, "Unsupported are intrinsics," option.
    pub fn set_unsupported_are_intrinsics(&mut self, unsupported_are_intrinsics: bool) {
        self.unsupported_are_intrinsics = unsupported_are_intrinsics;
    }

    /// Whether the translator should throw an error for unhandled instruction,
    /// or simply lift them to an intrinsic.
    ///
    /// By default, lifters throw an error when they encounter an architecture
    /// instruction for which they have no semantics. This is not appropriate
    /// for all analyses. Sometimes we just want as many semantics as we can
    /// get. This flag tells lifters to emit intrinsic operations for
    /// unsupported instructions.
    pub fn unsupported_are_intrinsics(&self) -> bool {
        self.unsupported_are_intrinsics
    }

    /// Add a manual edge to the translator logic. See documentation on
    /// `ManualEdge` for further details.
    pub fn add_manual_edge(&mut self, manual_edge: ManualEdge) {
        self.manual_edges.push(manual_edge);
    }

    /// Get the manual edges this translator should enforce
    pub fn manual_edges(&self) -> &[ManualEdge] {
        &self.manual_edges
    }
}

/// Create your options with the builder pattern.
///
/// For more details on the options, see `translator::Options`
pub struct OptionsBuilder {
    options: Options,
}

impl OptionsBuilder {
    /// Create a new builder for translator options.
    pub fn new() -> OptionsBuilder {
        OptionsBuilder {
            options: Options::default(),
        }
    }

    /// Set the, "Unsupported are intrinsics," option. By default this is false.
    pub fn unsupported_are_intrinsics(
        mut self,
        unsupported_are_intrinsics: bool,
    ) -> OptionsBuilder {
        self.options.unsupported_are_intrinsics = unsupported_are_intrinsics;
        self
    }

    pub fn add_manual_edge(mut self, manual_edge: ManualEdge) -> OptionsBuilder {
        self.options.add_manual_edge(manual_edge);
        self
    }

    pub fn build(self) -> Options {
        self.options
    }
}

impl default::Default for OptionsBuilder {
    fn default() -> OptionsBuilder {
        OptionsBuilder::new()
    }
}
