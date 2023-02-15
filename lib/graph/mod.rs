//! Implements a directed graph.

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::Error;

pub trait Vertex: Clone + Sync {
    // The index of this vertex.
    fn index(&self) -> usize;
    // A string to display in dot graphviz format.
    fn dot_label(&self) -> String;
    // Fill color in dot graphviz format.
    fn dot_fill_color(&self) -> String {
        "#ffddcc".to_string()
    }
    // Font color in dot graphviz format.
    fn dot_font_color(&self) -> String {
        "#000000".to_string()
    }
}

pub trait Edge: Clone + Sync {
    /// The index of the head vertex.
    fn head(&self) -> usize;
    /// The index of the tail vertex.
    fn tail(&self) -> usize;
    /// A string to display in dot graphviz format.
    fn dot_label(&self) -> String;
    // Style in dot graphviz format.
    fn dot_style(&self) -> String {
        "solid".to_string()
    }
    // Fill color in dot graphviz format.
    fn dot_fill_color(&self) -> String {
        "#000000".to_string()
    }
    // Font color in dot graphviz format.
    fn dot_font_color(&self) -> String {
        "#000000".to_string()
    }
    // Pen width in dot graphviz format.
    fn dot_pen_width(&self) -> f64 {
        1.0
    }
}

/// An empty vertex for creating structures when data is not required
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NullVertex {
    index: usize,
}

impl NullVertex {
    pub fn new(index: usize) -> NullVertex {
        NullVertex { index }
    }
}

impl Vertex for NullVertex {
    fn index(&self) -> usize {
        self.index
    }
    fn dot_label(&self) -> String {
        format!("{}", self.index)
    }
}

/// An empty edge for creating structures when data is not required
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NullEdge {
    head: usize,
    tail: usize,
}

impl NullEdge {
    pub fn new(head: usize, tail: usize) -> NullEdge {
        NullEdge { head, tail }
    }
}

impl Edge for NullEdge {
    fn head(&self) -> usize {
        self.head
    }
    fn tail(&self) -> usize {
        self.tail
    }
    fn dot_label(&self) -> String {
        format!("{} -> {}", self.head, self.tail)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Loop {
    header: usize,
    nodes: BTreeSet<usize>,
}

impl Loop {
    pub fn new(header: usize, nodes: BTreeSet<usize>) -> Self {
        Self { header, nodes }
    }

    /// The set of nodes part of this loop
    pub fn nodes(&self) -> &BTreeSet<usize> {
        &self.nodes
    }

    /// The loop header node
    pub fn header(&self) -> usize {
        self.header
    }

    /// The set of loop tail nodes
    pub fn tail(&self) -> BTreeSet<usize> {
        let mut tail_nodes = self.nodes.clone();
        tail_nodes.remove(&self.header);
        tail_nodes
    }

    /// Returns `true` if this loop is nesting another loop.
    pub fn is_nesting(&self, other: &Self) -> bool {
        self.header != other.header && self.nodes.contains(&other.header)
    }

    /// Returns `true` if this loop and another loop are disjoint.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        self.header != other.header
            && !self.nodes.contains(&other.header)
            && !other.nodes.contains(&self.header)
    }
}

impl Vertex for Loop {
    fn index(&self) -> usize {
        self.header
    }
    fn dot_label(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for Loop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Loop 0x{:X}: {{", self.header)?;
        let mut is_first = true;
        for node in &self.nodes {
            if !is_first {
                write!(f, ", ")?;
            }
            write!(f, "0x{:X}", node)?;
            is_first = false;
        }
        write!(f, "}}")
    }
}

pub type LoopTree = Graph<Loop, NullEdge>;

/// A directed graph.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Default)]
pub struct Graph<V: Vertex, E: Edge> {
    vertices: BTreeMap<usize, V>,
    edges: BTreeMap<(usize, usize), E>,
    successors: BTreeMap<usize, BTreeSet<usize>>,
    predecessors: BTreeMap<usize, BTreeSet<usize>>,
}

impl<V, E> Graph<V, E>
where
    V: Vertex,
    E: Edge,
{
    pub fn new() -> Graph<V, E> {
        Graph {
            vertices: BTreeMap::new(),
            edges: BTreeMap::new(),
            successors: BTreeMap::new(),
            predecessors: BTreeMap::new(),
        }
    }

    pub fn num_vertices(&self) -> usize {
        self.vertices.len()
    }

    /// Returns true if the vertex with the given index exists in this graph
    pub fn has_vertex(&self, index: usize) -> bool {
        self.vertices.contains_key(&index)
    }

    /// Removes a vertex, and all edges associated with that vertex.
    pub fn remove_vertex(&mut self, index: usize) -> Result<(), Error> {
        // TODO there's a lot of duplicated work in removing edges. Makes
        // debugging easier, but could be made much more efficient.
        if !self.has_vertex(index) {
            return Err(Error::GraphVertexNotFound(index));
        }

        // remove this vertex
        self.vertices.remove(&index);

        // find all edges that deal with this vertex
        let mut edges = FxHashSet::default();
        if let Some(successors) = self.successors.get(&index) {
            for successor in successors {
                edges.insert((index, *successor));
            }
        };
        if let Some(predecessors) = self.predecessors.get(&index) {
            for predecessor in predecessors {
                edges.insert((*predecessor, index));
            }
        };

        // remove all of those edges
        for edge in edges {
            self.remove_edge(edge.0, edge.1)?;
        }

        self.predecessors.remove(&index);
        self.successors.remove(&index);

        Ok(())
    }

    /// Removes all unreachable vertices from this graph.
    /// Unreachable means that there is no path from head to the vertex.
    pub fn remove_unreachable_vertices(&mut self, head: usize) -> Result<(), Error> {
        self.unreachable_vertices(head)?
            .iter()
            .for_each(|vertex| self.remove_vertex(*vertex).unwrap());
        Ok(())
    }

    /// Returns true if the edge with the given head and tail index exists in this graph
    pub fn has_edge(&self, head: usize, tail: usize) -> bool {
        self.edges.contains_key(&(head, tail))
    }

    /// Removes an edge
    pub fn remove_edge(&mut self, head: usize, tail: usize) -> Result<(), Error> {
        if !self.has_edge(head, tail) {
            return Err(Error::GraphEdgeNotFound(head, tail));
        }

        self.edges.remove(&(head, tail));

        self.predecessors.get_mut(&tail).unwrap().remove(&head);

        self.successors.get_mut(&head).unwrap().remove(&tail);

        Ok(())
    }

    /// Inserts a vertex into the graph.
    /// # Errors
    /// Error if the vertex already exists by index.
    pub fn insert_vertex(&mut self, v: V) -> Result<(), Error> {
        if self.vertices.contains_key(&v.index()) {
            return Err("duplicate vertex index".into());
        }
        self.vertices.insert(v.index(), v.clone());
        self.successors.insert(v.index(), BTreeSet::new());
        self.predecessors.insert(v.index(), BTreeSet::new());
        Ok(())
    }

    /// Inserts an edge into the graph.
    /// # Errors
    /// Error if the edge already exists by indices.
    pub fn insert_edge(&mut self, edge: E) -> Result<(), Error> {
        if self.edges.contains_key(&(edge.head(), edge.tail())) {
            return Err("duplicate edge".into());
        }
        if !self.vertices.contains_key(&edge.head()) {
            return Err(Error::GraphVertexNotFound(edge.head()));
        }
        if !self.vertices.contains_key(&edge.tail()) {
            return Err(Error::GraphVertexNotFound(edge.tail()));
        }

        self.edges.insert((edge.head(), edge.tail()), edge.clone());
        self.successors
            .get_mut(&edge.head())
            .unwrap()
            .insert(edge.tail());
        self.predecessors
            .get_mut(&edge.tail())
            .unwrap()
            .insert(edge.head());

        Ok(())
    }

    /// Returns all immediate successors of a vertex from the graph.
    pub fn successors(&self, index: usize) -> Result<Vec<&V>, Error> {
        if !self.vertices.contains_key(&index) {
            return Err(Error::GraphVertexNotFound(index));
        }

        let vertices = &self.successors[&index];

        Ok(vertices.iter().fold(Vec::new(), |mut v, index| {
            v.push(self.vertices.get(index).unwrap());
            v
        }))
    }

    /// Returns all immediate predecessors of a vertex from the graph.
    pub fn predecessors(&self, index: usize) -> Result<Vec<&V>, Error> {
        if !self.vertices.contains_key(&index) {
            return Err(Error::GraphVertexNotFound(index));
        }

        let vertices = &self.predecessors[&index];

        Ok(vertices.iter().fold(Vec::new(), |mut v, index| {
            v.push(self.vertices.get(index).unwrap());
            v
        }))
    }

    /// Returns the indices of all immediate successors of a vertex from the graph.
    pub fn successor_indices(&self, index: usize) -> Result<Vec<usize>, Error> {
        if !self.vertices.contains_key(&index) {
            return Err(Error::GraphVertexNotFound(index));
        }

        Ok(self.successors[&index].iter().cloned().collect())
    }

    /// Returns the indices of all immediate predecessors of a vertex from the graph.
    pub fn predecessor_indices(&self, index: usize) -> Result<Vec<usize>, Error> {
        if !self.vertices.contains_key(&index) {
            return Err(Error::GraphVertexNotFound(index));
        }

        Ok(self.predecessors[&index].iter().cloned().collect())
    }

    /// Returns all vertices which don't have any predecessors in the graph.
    pub fn vertices_without_predecessors(&self) -> Vec<&V> {
        self.vertices
            .values()
            .filter(|v| self.predecessors.get(&v.index()).unwrap().is_empty())
            .collect()
    }

    /// Returns all vertices which don't have any successors in the graph.
    pub fn vertices_without_successors(&self) -> Vec<&V> {
        self.vertices
            .values()
            .filter(|v| self.successors.get(&v.index()).unwrap().is_empty())
            .collect()
    }

    /// Computes the set of vertices unreachable from the given index.
    pub fn unreachable_vertices(&self, index: usize) -> Result<FxHashSet<usize>, Error> {
        let reachable_vertices = self.reachable_vertices(index)?;
        Ok(self
            .vertices
            .keys()
            .filter(|index| !reachable_vertices.contains(index))
            .cloned()
            .collect())
    }

    /// Computes the set of vertices reachable from the given index.
    pub fn reachable_vertices(&self, index: usize) -> Result<FxHashSet<usize>, Error> {
        if !self.has_vertex(index) {
            return Err(Error::GraphVertexNotFound(index));
        }

        let mut reachable_vertices: FxHashSet<usize> = FxHashSet::default();
        let mut queue: Vec<usize> = vec![index];

        reachable_vertices.insert(index);

        while let Some(vertex) = queue.pop() {
            self.successors
                .get(&vertex)
                .unwrap()
                .iter()
                .for_each(|&succ| {
                    if reachable_vertices.insert(succ) {
                        queue.push(succ)
                    }
                });
        }

        Ok(reachable_vertices)
    }

    /// Compute the pre order of all vertices in the graph
    pub fn compute_pre_order(&self, root: usize) -> Result<Vec<usize>, Error> {
        if !self.has_vertex(root) {
            return Err(Error::GraphVertexNotFound(root));
        }

        let mut visited: FxHashSet<usize> = FxHashSet::default();
        let mut stack: Vec<usize> = Vec::new();
        let mut order: Vec<usize> = Vec::new();

        stack.push(root);

        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }

            order.push(node);

            for &successor in &self.successors[&node] {
                stack.push(successor);
            }
        }

        Ok(order)
    }

    // Compute the post order of all vertices in the graph
    pub fn compute_post_order(&self, root: usize) -> Result<Vec<usize>, Error> {
        let mut visited: FxHashSet<usize> = FxHashSet::default();
        let mut order: Vec<usize> = Vec::new();

        fn dfs_walk<V: Vertex, E: Edge>(
            graph: &Graph<V, E>,
            node: usize,
            visited: &mut FxHashSet<usize>,
            order: &mut Vec<usize>,
        ) -> Result<(), Error> {
            visited.insert(node);
            for successor in &graph.successors[&node] {
                if !visited.contains(successor) {
                    dfs_walk(graph, *successor, visited, order)?;
                }
            }
            order.push(node);
            Ok(())
        }

        dfs_walk(self, root, &mut visited, &mut order)?;

        Ok(order)
    }

    /// Computes the dominance frontiers for all vertices in the graph
    pub fn compute_dominance_frontiers(
        &self,
        start_index: usize,
    ) -> Result<FxHashMap<usize, FxHashSet<usize>>, Error> {
        let mut df: FxHashMap<usize, FxHashSet<usize>> = FxHashMap::default();

        for vertex in &self.vertices {
            df.insert(*vertex.0, FxHashSet::default());
        }

        let idoms = self.compute_immediate_dominators(start_index)?;

        for vertex in &self.vertices {
            let vertex_index: usize = *vertex.0;

            if self.predecessors[&vertex_index].len() >= 2 {
                if !idoms.contains_key(&vertex_index) {
                    continue;
                }
                let idom = idoms[&vertex_index];

                for predecessor in &self.predecessors[&vertex_index] {
                    let mut runner = *predecessor;
                    while runner != idom {
                        df.get_mut(&runner).unwrap().insert(vertex_index);
                        if !idoms.contains_key(&runner) {
                            break;
                        }
                        runner = idoms[&runner];
                    }
                }
            }
        }

        // Special handling for the start node as it can be part of a loop.
        // This is necessary because we don't have a dedicated entry node.
        for predecessor in &self.predecessors[&start_index] {
            let mut runner = *predecessor;
            loop {
                df.get_mut(&runner).unwrap().insert(start_index);
                if !idoms.contains_key(&runner) {
                    break;
                }
                runner = idoms[&runner];
            }
        }

        Ok(df)
    }

    /// Computes immediate dominators for all vertices in the graph
    ///
    /// This implementation is based on the Semi-NCA algorithm described in:
    /// Georgiadis, Loukas: Linear-Time Algorithms for Dominators and Related Problems (thesis)
    /// <https://www.cs.princeton.edu/research/techreps/TR-737-05>
    pub fn compute_immediate_dominators(
        &self,
        root: usize,
    ) -> Result<FxHashMap<usize, usize>, Error> {
        if !self.vertices.contains_key(&root) {
            return Err(Error::GraphVertexNotFound(root));
        }

        let dfs = self.compute_dfs_tree(root)?;
        let dfs_pre_order = dfs.compute_pre_order(root)?;

        let dfs_parent = |vertex| dfs.predecessors[&vertex].iter().next().cloned();

        // DFS-numbering and reverse numbering (starting from 0 instead of 1 as in the paper)
        let dfs_number: FxHashMap<usize, usize> = dfs_pre_order
            .iter()
            .enumerate()
            .map(|(number, vertex)| (*vertex, number))
            .collect();
        let graph_number = &dfs_pre_order;

        let mut ancestor: FxHashMap<usize, Option<usize>> = FxHashMap::default();
        let mut label: FxHashMap<usize, usize> = FxHashMap::default();
        for &vertex in self.vertices.keys() {
            ancestor.insert(vertex, None);
            label.insert(vertex, dfs_number[&vertex]);
        }

        // Compute semidominators in reverse preorder (without root)
        let mut semi = FxHashMap::default();
        for &vertex in dfs_pre_order.iter().skip(1).rev() {
            let mut min_semi = std::usize::MAX;

            for &pred in &self.predecessors[&vertex] {
                if ancestor[&pred].is_some() {
                    compress(&mut ancestor, &mut label, pred);
                }
                min_semi = cmp::min(min_semi, label[&pred]);
            }

            semi.insert(vertex, min_semi);
            label.insert(vertex, min_semi);

            ancestor.insert(vertex, dfs_parent(vertex));
        }
        let semi = semi;

        fn compress(
            ancestor: &mut FxHashMap<usize, Option<usize>>,
            label: &mut FxHashMap<usize, usize>,
            v: usize,
        ) {
            let u = ancestor[&v].unwrap();
            if ancestor[&u].is_some() {
                compress(ancestor, label, u);
                if label[&u] < label[&v] {
                    label.insert(v, label[&u]);
                }
                ancestor.insert(v, ancestor[&u]);
            }
        }

        // Compute immediate dominators in preorder (without root)
        let mut idoms = FxHashMap::default();
        for &vertex in dfs_pre_order.iter().skip(1) {
            let mut idom = dfs_number[&dfs_parent(vertex).unwrap()];
            while idom > semi[&vertex] {
                idom = idoms[&idom];
            }
            idoms.insert(dfs_number[&vertex], idom);
        }
        let idoms = idoms;

        // Translate idoms from DFS-numbering back to graph indices
        let mut graph_idoms = FxHashMap::default();
        for (vertex, idom) in idoms {
            graph_idoms.insert(graph_number[vertex], graph_number[idom]);
        }
        Ok(graph_idoms)
    }

    /// Computes dominators for all vertices in the graph
    pub fn compute_dominators(
        &self,
        start_index: usize,
    ) -> Result<FxHashMap<usize, FxHashSet<usize>>, Error> {
        if !self.vertices.contains_key(&start_index) {
            return Err(Error::GraphVertexNotFound(start_index));
        }

        let dom_tree = self.compute_dominator_tree(start_index)?;
        let dom_tree_pre_oder = dom_tree.compute_pre_order(start_index)?;

        let mut dominators: FxHashMap<usize, FxHashSet<usize>> = FxHashMap::default();

        for vertex in dom_tree_pre_oder {
            let mut doms = FxHashSet::default();
            doms.insert(vertex);
            for pred in &dom_tree.predecessors[&vertex] {
                doms.extend(&dominators[pred])
            }
            dominators.insert(vertex, doms);
        }

        Ok(dominators)
    }

    /// Creates a dominator tree with NullVertex and NullEdge
    pub fn compute_dominator_tree(
        &self,
        start_index: usize,
    ) -> Result<Graph<NullVertex, NullEdge>, Error> {
        let mut graph = Graph::new();
        for vertex in &self.vertices {
            graph.insert_vertex(NullVertex::new(*vertex.0))?;
        }

        let idoms = self.compute_immediate_dominators(start_index)?;
        for (vertex, idom) in idoms {
            graph.insert_edge(NullEdge::new(idom, vertex))?;
        }

        Ok(graph)
    }

    /// Computes predecessors for all vertices in the graph
    ///
    /// The resulting sets include all predecessors for each vertex in the
    /// graph, not just immediate predecessors.
    ///
    /// Given A -> B -> C, both A and B will be in the set for C.
    pub fn compute_predecessors(&self) -> Result<FxHashMap<usize, FxHashSet<usize>>, Error> {
        let mut predecessors: FxHashMap<usize, FxHashSet<usize>> = FxHashMap::default();
        let mut queue: VecDeque<usize> = VecDeque::new();

        // initial population
        for vertex in &self.vertices {
            let mut preds = FxHashSet::default();
            for predecessor in &self.predecessors[vertex.0] {
                preds.insert(*predecessor);
            }
            predecessors.insert(*vertex.0, preds);
            queue.push_back(*vertex.0);
        }

        // for every vertex
        while let Some(vertex_index) = queue.pop_front() {
            let this_predecessors = predecessors.get(&vertex_index).unwrap().clone();

            for successor_index in &self.successors[&vertex_index] {
                let successor_predecessors = predecessors.get_mut(successor_index).unwrap();

                let mut changed = false;
                for predecessor in &this_predecessors {
                    changed |= successor_predecessors.insert(*predecessor);
                }

                if changed {
                    queue.push_back(*successor_index);
                }
            }
        }

        Ok(predecessors)
    }

    /// Creates a DFS tree with NullVertex and NullEdge
    pub fn compute_dfs_tree(
        &self,
        start_index: usize,
    ) -> Result<Graph<NullVertex, NullEdge>, Error> {
        if !self.has_vertex(start_index) {
            return Err(Error::GraphVertexNotFound(start_index));
        }

        let mut tree = Graph::new();
        let mut stack = Vec::new();

        tree.insert_vertex(NullVertex::new(start_index))?;
        for &successor in &self.successors[&start_index] {
            stack.push((start_index, successor));
        }

        while let Some((pred, index)) = stack.pop() {
            if tree.has_vertex(index) {
                continue;
            }

            tree.insert_vertex(NullVertex::new(index))?;
            tree.insert_edge(NullEdge::new(pred, index))?;

            for &successor in &self.successors[&index] {
                stack.push((index, successor));
            }
        }

        Ok(tree)
    }

    /// Creates an acyclic graph with NullVertex and NullEdge
    pub fn compute_acyclic(
        &self,
        start_index: usize,
    ) -> Result<Graph<NullVertex, NullEdge>, Error> {
        let mut graph = Graph::new();
        for vertex in &self.vertices {
            graph.insert_vertex(NullVertex::new(*vertex.0))?;
        }

        let predecessors = self.compute_predecessors()?;

        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        queue.push_back(start_index);

        while !queue.is_empty() {
            let vertex_index = queue.pop_front().unwrap();

            visited.insert(vertex_index);

            let vertex_predecessors = &predecessors[&vertex_index];

            for successor in &self.successors[&vertex_index] {
                // skip edges that would create a loop
                if visited.contains(successor) && vertex_predecessors.contains(successor) {
                    continue;
                }
                // successors we haven't seen yet get added to the queue
                if !visited.contains(successor) && !queue.contains(successor) {
                    queue.push_back(*successor);
                }

                graph.insert_edge(NullEdge::new(vertex_index, *successor))?;
            }
        }

        Ok(graph)
    }

    /// Determines if the graph is acyclic
    pub fn is_acyclic(&self, root: usize) -> bool {
        let mut permanent_marks: FxHashSet<usize> = FxHashSet::default();
        let mut temporary_marks: FxHashSet<usize> = FxHashSet::default();

        fn dfs_is_acyclic<V: Vertex, E: Edge>(
            graph: &Graph<V, E>,
            node: usize,
            permanent_marks: &mut FxHashSet<usize>,
            temporary_marks: &mut FxHashSet<usize>,
        ) -> bool {
            if permanent_marks.contains(&node) {
                return true;
            }
            if temporary_marks.contains(&node) {
                return false;
            }

            temporary_marks.insert(node);
            let successors_are_acyclic = graph.successors[&node].iter().all(|successor| {
                dfs_is_acyclic(graph, *successor, permanent_marks, temporary_marks)
            });
            if !successors_are_acyclic {
                return false;
            }
            temporary_marks.remove(&node);

            permanent_marks.insert(node);
            true
        }

        dfs_is_acyclic(self, root, &mut permanent_marks, &mut temporary_marks)
    }

    /// Computes the set of back edges
    ///
    /// Back edges are edges whose heads dominate their tails.
    fn compute_back_edges(&self, head: usize) -> Result<FxHashSet<(usize, usize)>, Error> {
        let mut back_edges: FxHashSet<(usize, usize)> = FxHashSet::default();

        for (node, dominators) in self.compute_dominators(head)? {
            for successor in &self.successors[&node] {
                if dominators.contains(successor) {
                    back_edges.insert((node, *successor));
                }
            }
        }

        Ok(back_edges)
    }

    /// Determines if the graph is reducible.
    pub fn is_reducible(&self, head: usize) -> Result<bool, Error> {
        let back_edges = self.compute_back_edges(head)?;

        // Build a graph without back edges, a.k.a. forward edges (FE) graph.
        let mut fe_graph = Graph::new();
        for index in self.vertices.keys() {
            fe_graph.insert_vertex(NullVertex::new(*index))?;
        }
        for edge in self.edges.keys() {
            if !back_edges.contains(edge) {
                fe_graph.insert_edge(NullEdge::new(edge.0, edge.1))?;
            }
        }

        // Graph is reducible iff the FE graph is acyclic and every node is reachable from head.
        let every_node_is_reachable = fe_graph.unreachable_vertices(head)?.is_empty();
        Ok(every_node_is_reachable && fe_graph.is_acyclic(head))
    }

    /// Computes the set of natural loops in the graph
    pub fn compute_loops(&self, head: usize) -> Result<Vec<Loop>, Error> {
        let mut loops: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

        // For each back edge compute the set of nodes part of the loop
        for (tail, header) in self.compute_back_edges(head)? {
            let nodes = loops.entry(header).or_default();
            let mut queue: Vec<usize> = Vec::new();

            nodes.insert(header);

            if nodes.insert(tail) {
                queue.push(tail);
            }

            while let Some(node) = queue.pop() {
                for &predecessor in &self.predecessors[&node] {
                    if nodes.insert(predecessor) {
                        queue.push(predecessor);
                    }
                }
            }
        }

        Ok(loops
            .iter()
            .map(|(&header, nodes)| Loop::new(header, nodes.clone()))
            .collect())
    }

    /// Computes the loop tree of all natural loops in the graph
    ///
    /// If loop `l1` is nested in loop `l2`, `l1` is a child node of `l2` in the loop tree.
    pub fn compute_loop_tree(&self, head: usize) -> Result<LoopTree, Error> {
        let mut tree = LoopTree::new();

        let loops = self.compute_loops(head)?;
        for l in &loops {
            tree.insert_vertex(l.clone())?;
        }

        for l1 in &loops {
            for l2 in &loops {
                if l1.is_nesting(l2) {
                    tree.insert_edge(NullEdge::new(l1.header(), l2.header()))?;
                }
            }
        }

        Ok(tree)
    }

    /// Computes the topological ordering of all vertices in the graph
    pub fn compute_topological_ordering(&self) -> Result<Vec<usize>, Error> {
        let mut permanent_marks: FxHashSet<usize> = FxHashSet::default();
        let mut temporary_marks: FxHashSet<usize> = FxHashSet::default();
        let mut order: Vec<usize> = Vec::new();

        fn dfs_walk<V: Vertex, E: Edge>(
            graph: &Graph<V, E>,
            node: usize,
            permanent_marks: &mut FxHashSet<usize>,
            temporary_marks: &mut FxHashSet<usize>,
            order: &mut Vec<usize>,
        ) -> Result<(), Error> {
            if permanent_marks.contains(&node) {
                return Ok(());
            }
            if temporary_marks.contains(&node) {
                return Err("Graph contains a loop".into());
            }

            temporary_marks.insert(node);
            for successor in &graph.successors[&node] {
                dfs_walk(graph, *successor, permanent_marks, temporary_marks, order)?;
            }
            temporary_marks.remove(&node);
            permanent_marks.insert(node);
            order.push(node);
            Ok(())
        }

        for node in self.vertices.keys() {
            dfs_walk(
                self,
                *node,
                &mut permanent_marks,
                &mut temporary_marks,
                &mut order,
            )?;
        }

        Ok(order.into_iter().rev().collect())
    }

    /// Returns all vertices in the graph.
    pub fn vertices(&self) -> Vec<&V> {
        self.vertices.values().collect()
    }

    pub fn vertices_mut(&mut self) -> Vec<&mut V> {
        let mut vec = Vec::new();
        for vertex in &mut self.vertices {
            vec.push(vertex.1);
        }
        vec
    }

    /// Fetches an index from the graph by index.
    pub fn vertex(&self, index: usize) -> Result<&V, Error> {
        self.vertices
            .get(&index)
            .ok_or(Error::GraphVertexNotFound(index))
    }

    // Fetches a mutable instance of a vertex.
    pub fn vertex_mut(&mut self, index: usize) -> Result<&mut V, Error> {
        self.vertices
            .get_mut(&index)
            .ok_or(Error::GraphVertexNotFound(index))
    }

    pub fn edge(&self, head: usize, tail: usize) -> Result<&E, Error> {
        self.edges
            .get(&(head, tail))
            .ok_or(Error::GraphEdgeNotFound(head, tail))
    }

    pub fn edge_mut(&mut self, head: usize, tail: usize) -> Result<&mut E, Error> {
        self.edges
            .get_mut(&(head, tail))
            .ok_or(Error::GraphEdgeNotFound(head, tail))
    }

    /// Get a reference to every `Edge` in the `Graph`.
    pub fn edges(&self) -> Vec<&E> {
        self.edges.values().collect()
    }

    /// Get a mutable reference to every `Edge` in the `Graph`.
    pub fn edges_mut(&mut self) -> Vec<&mut E> {
        let mut vec = Vec::new();
        for edge in &mut self.edges {
            vec.push(edge.1);
        }
        vec
    }

    /// Return all edges out for a vertex
    pub fn edges_out(&self, index: usize) -> Result<Vec<&E>, Error> {
        self.successors
            .get(&index)
            .map(|succs| {
                succs
                    .iter()
                    .map(|succ| &self.edges[&(index, *succ)])
                    .collect()
            })
            .ok_or(Error::GraphVertexNotFound(index))
    }

    /// Return all edges in for a vertex
    pub fn edges_in(&self, index: usize) -> Result<Vec<&E>, Error> {
        self.predecessors
            .get(&index)
            .map(|preds| {
                preds
                    .iter()
                    .map(|pred| &self.edges[&(*pred, index)])
                    .collect()
            })
            .ok_or(Error::GraphVertexNotFound(index))
    }

    /// Returns a string in the graphviz format
    pub fn dot_graph(&self) -> String {
        let vertices = self
            .vertices
            .iter()
            .map(|v| {
                let label = v.1.dot_label().replace('\n', "\\l");
                let fill_color = v.1.dot_fill_color();
                let font_color = v.1.dot_font_color();
                format!(
                    "{} [shape=\"box\", label=\"{}\", style=\"filled\", fillcolor=\"{}\", fontcolor=\"{}\"];",
                    v.1.index(),
                    label,
                    fill_color,
                    font_color,
                )
            })
            .collect::<Vec<String>>();

        let edges = self
            .edges
            .iter()
            .map(|e| {
                let label = e.1.dot_label().replace('\n', "\\l");
                let style = e.1.dot_style();
                let fill_color = e.1.dot_fill_color();
                let font_color = e.1.dot_font_color();
                let pen_width = e.1.dot_pen_width();
                format!("{} -> {} [label=\"{}\", style=\"{}\", color=\"{}\", fontcolor=\"{}\", penwidth=\"{}\"];",
                        e.1.head(), e.1.tail(), label, style, fill_color, font_color, pen_width)
            })
            .collect::<Vec<String>>();

        let options = vec![
            "graph [fontname = \"Courier New\", splines=\"polyline\"]",
            "node [fontname = \"Courier New\"]",
            "edge [fontname = \"Courier New\"]",
        ];

        format!(
            "digraph G {{\n{}\n\n{}\n{}\n}}",
            options.join("\n"),
            vertices.join("\n"),
            edges.join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Vertex for usize {
        fn index(&self) -> usize {
            *self
        }

        fn dot_label(&self) -> String {
            self.to_string()
        }
    }

    impl Edge for (usize, usize) {
        fn head(&self) -> usize {
            self.0
        }

        fn tail(&self) -> usize {
            self.1
        }

        fn dot_label(&self) -> String {
            format!("{} -> {}", self.0, self.1)
        }
    }

    /**
     *           +--> 3 +-+
     *          /          \
     *         | +--> 4 +--+
     *         |/          |
     *         +           v
     * 1 +---> 2 <-------+ 5
     *         +
     *         |
     *         v
     *         6
     *
     * From: https://en.wikipedia.org/wiki/Dominator_(graph_theory)
     */
    fn create_test_graph() -> Graph<usize, (usize, usize)> {
        let mut graph = Graph::new();

        graph.insert_vertex(1).unwrap();
        graph.insert_vertex(2).unwrap();
        graph.insert_vertex(3).unwrap();
        graph.insert_vertex(4).unwrap();
        graph.insert_vertex(5).unwrap();
        graph.insert_vertex(6).unwrap();

        graph.insert_edge((1, 2)).unwrap();
        graph.insert_edge((2, 3)).unwrap();
        graph.insert_edge((2, 4)).unwrap();
        graph.insert_edge((2, 6)).unwrap();
        graph.insert_edge((3, 5)).unwrap();
        graph.insert_edge((4, 5)).unwrap();
        graph.insert_edge((5, 2)).unwrap();

        graph
    }

    #[test]
    fn test_successors() {
        let graph = create_test_graph();

        assert_eq!(graph.successors(2).unwrap(), vec![&3, &4, &6]);

        let empty_vertex_list: Vec<&usize> = vec![];
        assert_eq!(graph.successors(6).unwrap(), empty_vertex_list);

        // vertex 7 does not exist
        assert!(graph.successors(7).is_err());
    }

    #[test]
    fn test_predecessors() {
        let graph = create_test_graph();

        let empty_vertex_list: Vec<&usize> = vec![];
        assert_eq!(graph.predecessors(1).unwrap(), empty_vertex_list);

        assert_eq!(graph.predecessors(2).unwrap(), vec![&1, &5]);

        // vertex 7 does not exist
        assert!(graph.successors(7).is_err());
    }

    #[test]
    fn test_pre_order() {
        let graph = create_test_graph();

        assert_eq!(graph.compute_pre_order(1).unwrap(), vec![1, 2, 6, 4, 5, 3]);

        assert_eq!(graph.compute_pre_order(5).unwrap(), vec![5, 2, 6, 4, 3]);
    }

    #[test]
    fn test_post_order() {
        let graph = create_test_graph();

        assert_eq!(graph.compute_post_order(1).unwrap(), vec![5, 3, 4, 6, 2, 1]);

        assert_eq!(graph.compute_post_order(5).unwrap(), vec![3, 4, 6, 2, 5]);
    }

    #[test]
    fn test_dominance_frontiers() {
        let graph = create_test_graph();
        let dominance_frontiers = graph.compute_dominance_frontiers(1).unwrap();

        assert_eq!(
            dominance_frontiers.get(&1).unwrap(),
            &vec![].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&2).unwrap(),
            &vec![2].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&3).unwrap(),
            &vec![5].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&4).unwrap(),
            &vec![5].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&5).unwrap(),
            &vec![2].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&6).unwrap(),
            &vec![].into_iter().collect()
        );
    }

    #[test]
    fn test_dominance_frontiers_of_graph_with_start_node_in_loop() {
        //      +-------+
        //      |       |
        //      v       +
        // ---> 1 +---> 2 +---> 3
        //      +               /\
        //      |               |
        //      +---------------+
        //
        // Simplified version of the example given in
        // https://www.seas.harvard.edu/courses/cs252/2011sp/slides/Lec04-SSA.pdf
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((1, 3)).unwrap();
            graph.insert_edge((2, 1)).unwrap();
            graph.insert_edge((2, 3)).unwrap();

            graph
        };

        let dominance_frontiers = graph.compute_dominance_frontiers(1).unwrap();

        assert_eq!(
            dominance_frontiers.get(&1).unwrap(),
            &vec![1].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&2).unwrap(),
            &vec![1, 3].into_iter().collect()
        );

        assert_eq!(
            dominance_frontiers.get(&3).unwrap(),
            &vec![].into_iter().collect()
        );
    }

    #[test]
    fn test_immediate_dominators_graph1() {
        let graph = create_test_graph();
        let idoms = graph.compute_immediate_dominators(1).unwrap();

        assert!(idoms.get(&1).is_none());
        assert_eq!(*idoms.get(&2).unwrap(), 1);
        assert_eq!(*idoms.get(&3).unwrap(), 2);
        assert_eq!(*idoms.get(&4).unwrap(), 2);
        assert_eq!(*idoms.get(&5).unwrap(), 2);
        assert_eq!(*idoms.get(&6).unwrap(), 2);
    }

    #[test]
    fn test_immediate_dominators_graph2() {
        //      |
        //      v
        // +--> 0
        // |    |
        // | +--+--+
        // | |     |
        // | v     v
        // | 1     2 +-+
        // | |     |   |
        // | +--+--+   |
        // |    |      |
        // |    v      |
        // +--+ 3      |
        //      |      |
        //      v      |
        //      4 <----+
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(0).unwrap();
            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();

            graph.insert_edge((0, 1)).unwrap();
            graph.insert_edge((0, 2)).unwrap();
            graph.insert_edge((1, 3)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((2, 4)).unwrap();
            graph.insert_edge((3, 0)).unwrap();
            graph.insert_edge((3, 4)).unwrap();

            graph
        };

        let idoms = graph.compute_immediate_dominators(0).unwrap();

        assert!(idoms.get(&0).is_none());
        assert_eq!(*idoms.get(&1).unwrap(), 0);
        assert_eq!(*idoms.get(&2).unwrap(), 0);
        assert_eq!(*idoms.get(&3).unwrap(), 0);
        assert_eq!(*idoms.get(&4).unwrap(), 0);
    }

    #[test]
    fn test_dominators() {
        let graph = create_test_graph();
        let dominators = graph.compute_dominators(1).unwrap();

        assert_eq!(dominators.get(&1).unwrap(), &vec![1].into_iter().collect());

        assert_eq!(
            dominators.get(&2).unwrap(),
            &vec![1, 2].into_iter().collect()
        );

        assert_eq!(
            dominators.get(&3).unwrap(),
            &vec![1, 2, 3].into_iter().collect()
        );

        assert_eq!(
            dominators.get(&4).unwrap(),
            &vec![1, 2, 4].into_iter().collect()
        );

        assert_eq!(
            dominators.get(&5).unwrap(),
            &vec![1, 2, 5].into_iter().collect()
        );

        assert_eq!(
            dominators.get(&6).unwrap(),
            &vec![1, 2, 6].into_iter().collect()
        );
    }

    #[test]
    fn test_dominator_tree() {
        let graph = create_test_graph();
        let dominator_tree = graph.compute_dominator_tree(1).unwrap();

        // Expected:
        // 1 +---> 2 +---> 3
        //           |
        //           +---> 4
        //           |
        //           +---> 5
        //           |
        //           +---> 6
        assert_eq!(dominator_tree.edges().len(), 5);
        assert!(dominator_tree.edge(1, 2).is_ok());
        assert!(dominator_tree.edge(2, 3).is_ok());
        assert!(dominator_tree.edge(2, 4).is_ok());
        assert!(dominator_tree.edge(2, 5).is_ok());
        assert!(dominator_tree.edge(2, 6).is_ok());
    }

    #[test]
    fn test_all_predecessors() {
        let graph = create_test_graph();
        let predecessors = graph.compute_predecessors().unwrap();

        assert_eq!(predecessors.get(&1).unwrap(), &vec![].into_iter().collect());

        assert_eq!(
            predecessors.get(&2).unwrap(),
            &vec![1, 2, 3, 4, 5].into_iter().collect()
        );
    }

    #[test]
    fn test_topological_ordering_should_return_error_for_cyclic_graph() {
        let graph = create_test_graph();
        assert!(graph.compute_topological_ordering().is_err());
    }

    #[test]
    fn test_topological_ordering() {
        // ---> 1 +---> 2 +-+-> 3 +---> 4
        //      +          /      \     /\
        //      |         /        \    |
        //      +-----> 5 +---> 6 +-+-> 7
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();
            graph.insert_vertex(5).unwrap();
            graph.insert_vertex(6).unwrap();
            graph.insert_vertex(7).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((2, 5)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((3, 4)).unwrap();
            graph.insert_edge((3, 7)).unwrap();
            graph.insert_edge((5, 3)).unwrap();
            graph.insert_edge((5, 6)).unwrap();
            graph.insert_edge((6, 7)).unwrap();
            graph.insert_edge((7, 4)).unwrap();

            graph
        };

        assert_eq!(
            graph.compute_topological_ordering().unwrap(),
            vec![1, 2, 5, 6, 3, 7, 4]
        );
    }

    #[test]
    fn test_vertices_without_predecessors() {
        let graph = create_test_graph();
        let vertices = graph.vertices_without_predecessors();
        assert_eq!(vertices, [graph.vertex(1).unwrap()]);
    }

    #[test]
    fn test_vertices_without_successors() {
        let graph = create_test_graph();
        let vertices = graph.vertices_without_successors();
        assert_eq!(vertices, [graph.vertex(6).unwrap()]);
    }

    #[test]
    fn test_remove_unreachable_vertices() {
        let mut graph = Graph::new();

        // reachable
        graph.insert_vertex(1).unwrap();
        graph.insert_vertex(2).unwrap();
        graph.insert_edge((1, 2)).unwrap();

        // unreachable
        graph.insert_vertex(3).unwrap();
        graph.insert_vertex(4).unwrap();
        graph.insert_vertex(5).unwrap();
        graph.insert_edge((4, 5)).unwrap();
        graph.insert_edge((4, 2)).unwrap();

        graph.remove_unreachable_vertices(1).unwrap();

        assert_eq!(graph.num_vertices(), 2);
        assert!(graph.has_vertex(1));
        assert!(graph.has_vertex(2));
    }

    #[test]
    fn test_reachable_vertices() {
        let mut graph = Graph::new();

        // reachable from 1
        graph.insert_vertex(1).unwrap();
        graph.insert_vertex(2).unwrap();
        graph.insert_edge((1, 2)).unwrap();

        // unreachable from 1
        graph.insert_vertex(3).unwrap();
        graph.insert_vertex(4).unwrap();
        graph.insert_vertex(5).unwrap();
        graph.insert_edge((4, 5)).unwrap();
        graph.insert_edge((4, 2)).unwrap();

        let reachable_vertices = graph.reachable_vertices(1).unwrap();

        assert_eq!(reachable_vertices.len(), 2);
        assert!(reachable_vertices.contains(&1));
        assert!(reachable_vertices.contains(&2));
    }

    #[test]
    fn test_unreachable_vertices() {
        let mut graph = Graph::new();

        // reachable from 1
        graph.insert_vertex(1).unwrap();
        graph.insert_vertex(2).unwrap();
        graph.insert_edge((1, 2)).unwrap();

        // unreachable from 1
        graph.insert_vertex(3).unwrap();
        graph.insert_vertex(4).unwrap();
        graph.insert_vertex(5).unwrap();
        graph.insert_edge((4, 5)).unwrap();
        graph.insert_edge((4, 2)).unwrap();

        let unreachable_vertices = graph.unreachable_vertices(1).unwrap();

        assert_eq!(unreachable_vertices.len(), 3);
        assert!(unreachable_vertices.contains(&3));
        assert!(unreachable_vertices.contains(&4));
        assert!(unreachable_vertices.contains(&5));
    }

    #[test]
    fn test_is_acyclic_should_return_false_for_cyclic_graph() {
        let graph = create_test_graph();
        assert_eq!(graph.is_acyclic(1), false);
    }

    #[test]
    fn test_is_acyclic_should_return_true_for_acyclic_graph() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((1, 3)).unwrap();
            graph.insert_edge((2, 3)).unwrap();

            graph
        };

        assert!(graph.is_acyclic(1));
    }

    #[test]
    fn test_is_reducible_should_return_false_for_irreducible_graph() {
        // Loop 2-3 with two loop entries 2 & 3 -> irreducible
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((1, 3)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((3, 2)).unwrap();

            graph
        };

        assert_eq!(graph.is_reducible(1).unwrap(), false);
    }

    #[test]
    fn test_is_reducible_should_return_true_for_reducible_graph() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap(); // loop header
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((2, 4)).unwrap();
            graph.insert_edge((3, 1)).unwrap(); // back edge

            graph
        };

        assert!(graph.is_reducible(1).unwrap());
    }

    #[test]
    fn test_compute_loops_single_loop() {
        let graph = create_test_graph();

        let loops = graph.compute_loops(1).unwrap();

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header(), 2);
        assert_eq!(loops[0].nodes(), &vec![2, 3, 4, 5].into_iter().collect());
    }

    #[test]
    fn test_compute_loops_nested_loops() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();
            graph.insert_vertex(5).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((3, 4)).unwrap();
            graph.insert_edge((3, 2)).unwrap(); // back edge
            graph.insert_edge((4, 5)).unwrap();
            graph.insert_edge((4, 1)).unwrap(); // back edge

            graph
        };

        let loops = graph.compute_loops(1).unwrap();

        assert_eq!(loops.len(), 2);
        assert!(loops.contains(&Loop::new(1, vec![1, 2, 3, 4].into_iter().collect())));
        assert!(loops.contains(&Loop::new(2, vec![2, 3].into_iter().collect())));
    }

    #[test]
    fn test_compute_loops_disjoint_loops() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();
            graph.insert_vertex(5).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((2, 1)).unwrap(); // back edge
            graph.insert_edge((3, 4)).unwrap();
            graph.insert_edge((4, 5)).unwrap();
            graph.insert_edge((4, 3)).unwrap(); // back edge

            graph
        };

        let loops = graph.compute_loops(1).unwrap();

        assert_eq!(loops.len(), 2);
        assert!(loops.contains(&Loop::new(1, vec![1, 2].into_iter().collect())));
        assert!(loops.contains(&Loop::new(3, vec![3, 4].into_iter().collect())));
    }

    #[test]
    fn test_compute_loops_self_loop() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((2, 2)).unwrap(); // back edge

            graph
        };

        let loops = graph.compute_loops(1).unwrap();

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header(), 2);
        assert_eq!(loops[0].nodes(), &vec![2].into_iter().collect());
    }

    #[test]
    fn test_compute_loops_should_combine_loops_with_same_header() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((1, 3)).unwrap();
            graph.insert_edge((2, 1)).unwrap(); // back edge
            graph.insert_edge((3, 1)).unwrap(); // back edge

            graph
        };

        let loops = graph.compute_loops(1).unwrap();

        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header(), 1);
        assert_eq!(loops[0].nodes(), &vec![1, 2, 3].into_iter().collect());
    }

    #[test]
    fn test_compute_dfs_tree() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();
            graph.insert_vertex(5).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((1, 3)).unwrap();
            graph.insert_edge((1, 4)).unwrap();
            graph.insert_edge((2, 5)).unwrap();
            graph.insert_edge((3, 2)).unwrap();

            graph
        };

        let expected_tree = {
            let mut tree = Graph::new();

            // visit 1 -> stack [(1,2), (1,3), (1,4)]
            tree.insert_vertex(NullVertex::new(1)).unwrap();
            // visit 4 -> stack [(1,2), (1,3)]
            tree.insert_vertex(NullVertex::new(4)).unwrap();
            tree.insert_edge(NullEdge::new(1, 4)).unwrap();
            // visit 3 -> stack [(1,2), (3,2)]
            tree.insert_vertex(NullVertex::new(3)).unwrap();
            tree.insert_edge(NullEdge::new(1, 3)).unwrap();
            // visit 2 -> stack [(1,2), (2,5)]
            tree.insert_vertex(NullVertex::new(2)).unwrap();
            tree.insert_edge(NullEdge::new(3, 2)).unwrap();
            // visit 5 -> stack [(1,2)]
            tree.insert_vertex(NullVertex::new(5)).unwrap();
            tree.insert_edge(NullEdge::new(2, 5)).unwrap();
            // skip 2 -> stack []

            tree
        };

        assert_eq!(expected_tree, graph.compute_dfs_tree(1).unwrap());
    }

    #[test]
    fn test_compute_loop_tree() {
        let graph = {
            let mut graph = Graph::new();

            graph.insert_vertex(1).unwrap();
            graph.insert_vertex(2).unwrap();
            graph.insert_vertex(3).unwrap();
            graph.insert_vertex(4).unwrap();

            graph.insert_edge((1, 2)).unwrap();
            graph.insert_edge((2, 2)).unwrap(); // self loop
            graph.insert_edge((2, 3)).unwrap();
            graph.insert_edge((3, 1)).unwrap(); // back edge to 1
            graph.insert_edge((3, 4)).unwrap();
            graph.insert_edge((4, 4)).unwrap(); // self loop

            graph
        };

        let expected_loop_tree = {
            let mut tree = LoopTree::new();

            tree.insert_vertex(Loop::new(1, vec![1, 2, 3].into_iter().collect()))
                .unwrap();
            tree.insert_vertex(Loop::new(2, vec![2].into_iter().collect()))
                .unwrap();
            tree.insert_vertex(Loop::new(4, vec![4].into_iter().collect()))
                .unwrap();

            tree.insert_edge(NullEdge::new(1, 2)).unwrap(); // loop 2 is nested in loop 1

            tree
        };

        let loop_tree = graph.compute_loop_tree(1).unwrap();
        assert_eq!(expected_loop_tree, loop_tree);
    }

    #[test]
    fn test_remove_vertex() {
        // GIVEN
        let mut graph = Graph::new();

        graph.insert_vertex(1).unwrap();
        graph.insert_vertex(2).unwrap();
        graph.insert_vertex(3).unwrap();

        graph.insert_edge((1, 2)).unwrap(); // ingoing
        graph.insert_edge((2, 3)).unwrap(); // outgoing
        graph.insert_edge((1, 3)).unwrap();

        // WHEN
        graph.remove_vertex(2).unwrap();

        // THEN should have removed vertex 2 and ingoing/outgoing edges
        assert_eq!(vec![&1, &3], graph.vertices());
        assert_eq!(vec![&(1, 3)], graph.edges());
    }

    #[test]
    fn test_remove_vertex_with_self_loop() {
        // GIVEN
        let mut graph = Graph::new();

        graph.insert_vertex(1).unwrap();
        graph.insert_edge((1, 1)).unwrap(); // self loop

        // WHEN
        graph.remove_vertex(1).unwrap();

        // THEN should have removed vertex 1 and self loop
        assert!(graph.vertices().is_empty());
        assert!(graph.edges().is_empty());
    }
}
