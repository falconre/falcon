//! Implements a directed graph.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::error::*;

pub trait Vertex: Clone + Sync {
    // The index of this vertex.
    fn index(&self) -> usize;
    // A string to display in dot graphviz format.
    fn dot_label(&self) -> String;
}

pub trait Edge: Clone + Sync {
    /// The index of the head vertex.
    fn head(&self) -> usize;
    /// The index of the tail vertex.
    fn tail(&self) -> usize;
    /// A string to display in dot graphviz format.
    fn dot_label(&self) -> String;
}

/// An empty vertex for creating structures when data is not required
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NullVertex {
    index: usize,
}

impl NullVertex {
    pub fn new(index: usize) -> NullVertex {
        NullVertex { index: index }
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
        NullEdge {
            head: head,
            tail: tail,
        }
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

/// A directed graph.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Graph<V: Vertex, E: Edge> {
    head: Option<usize>,
    vertices: BTreeMap<usize, V>,
    edges: BTreeMap<(usize, usize), E>,
    edges_out: BTreeMap<usize, Vec<E>>,
    edges_in: BTreeMap<usize, Vec<E>>,
}

impl<V, E> Graph<V, E>
where
    V: Vertex,
    E: Edge,
{
    pub fn new() -> Graph<V, E> {
        Graph {
            head: None,
            vertices: BTreeMap::new(),
            edges: BTreeMap::new(),
            edges_out: BTreeMap::new(),
            edges_in: BTreeMap::new(),
        }
    }

    pub fn num_vertices(&self) -> usize {
        self.vertices.len()
    }

    /// Returns true if the vertex with the given index exists in this graph
    pub fn has_vertex(&self, index: usize) -> bool {
        self.vertices.contains_key(&index)
    }

    /// Sets the head of this graph.
    pub fn set_head(&mut self, index: usize) -> Result<()> {
        if !self.vertices.contains_key(&index) {
            return Err("Cannot set head for index that does not exist".into());
        }
        self.head = Some(index);
        Ok(())
    }

    /// Returns the head of this graph.
    pub fn head(&self) -> Option<usize> {
        self.head
    }

    /// Removes a vertex, and all edges associated with that vertex.
    pub fn remove_vertex(&mut self, index: usize) -> Result<()> {
        // TODO there's a lot of duplicated work in removing edges. Makes
        // debugging easier, but could be made much more efficient.
        if !self.has_vertex(index) {
            bail!("vertex does not exist");
        }

        // remove this vertex
        self.vertices.remove(&index);

        // find all edges that deal with this vertex
        let mut edges = Vec::new();
        if let Some(edges_out) = self.edges_out.get(&index) {
            for edge in edges_out {
                edges.push((edge.head(), edge.tail()));
            }
        };
        if let Some(edges_in) = self.edges_in.get(&index) {
            for edge in edges_in {
                edges.push((edge.head(), edge.tail()));
            }
        };

        // remove all of those edges
        for edge in edges {
            self.remove_edge(edge.0, edge.1)?;
        }

        self.edges_in.remove(&index);
        self.edges_out.remove(&index);

        Ok(())
    }

    /// Removes an edge
    pub fn remove_edge(&mut self, head: usize, tail: usize) -> Result<()> {
        if !self.edges.contains_key(&(head, tail)) {
            bail!("edge does not exist");
        }

        self.edges.remove(&(head, tail));

        // find the index of this edge in edges_out
        let mut index = None;
        let edges_out = self.edges_out.get_mut(&head).unwrap();
        for (i, edge) in edges_out.iter().enumerate() {
            if edge.head() == head && edge.tail() == tail {
                index = Some(i);
                break;
            }
        }

        // remove this edge by index in edges_out
        edges_out.remove(index.unwrap());

        // find the index of this edge in edges_in
        let mut index = None;
        let edges_in = self.edges_in.get_mut(&tail).unwrap();
        for (i, edge) in edges_in.iter().enumerate() {
            if edge.head() == head && edge.tail() == tail {
                index = Some(i);
                break;
            }
        }

        // remove this edge by index in edges_in
        edges_in.remove(index.unwrap());

        Ok(())
    }

    /// Inserts a vertex into the graph.
    /// # Errors
    /// Error if the vertex already exists by index.
    pub fn insert_vertex(&mut self, v: V) -> Result<()> {
        if self.vertices.contains_key(&v.index()) {
            return Err("duplicate vertex index".into());
        }
        self.vertices.insert(v.index(), v.clone());
        self.edges_out.insert(v.index(), Vec::new());
        self.edges_in.insert(v.index(), Vec::new());
        Ok(())
    }

    /// Inserts an edge into the graph.
    /// # Errors
    /// Error if the edge already exists by indices.
    pub fn insert_edge(&mut self, edge: E) -> Result<()> {
        if self.edges.contains_key(&(edge.head(), edge.tail())) {
            return Err("duplicate edge".into());
        }

        self.edges.insert((edge.head(), edge.tail()), edge.clone());
        self.edges_out
            .get_mut(&edge.head())
            .map(|v| v.push(edge.clone()));
        self.edges_in
            .get_mut(&edge.tail())
            .map(|v| v.push(edge.clone()));

        Ok(())
    }

    /// Returns all immediate successors of a vertex from the graph.
    pub fn successors(&self, index: usize) -> Result<Vec<&V>> {
        if !self.vertices.contains_key(&index) {
            bail!(
                "Vertex {} does not exist and therefor has no successors",
                index
            );
        }

        let vertices = self.edges_out[&index].iter().map(|e| self.vertex(e.tail()));

        Ok(vertices.fold(Vec::new(), |mut v, vx| {
            v.push(vx.unwrap());
            v
        }))
    }

    /// Returns all immediate predecessors of a vertex from the graph.
    pub fn predecessors(&self, index: usize) -> Result<Vec<&V>> {
        if !self.vertices.contains_key(&index) {
            bail!(
                "Vertex {} does not exist and therefor has no predecessors",
                index
            );
        }

        let vertices = self.edges_in[&index].iter().map(|e| self.vertex(e.head()));

        Ok(vertices.fold(Vec::new(), |mut v, vx| {
            v.push(vx.unwrap());
            v
        }))
    }

    // Compute the post order of all vertices in the graph
    pub fn compute_post_order(&self, root: usize) -> Result<Vec<usize>> {
        let mut visited: HashSet<usize> = HashSet::new();
        let mut order: Vec<usize> = Vec::new();

        fn dfs_walk<V: Vertex, E: Edge>(
            graph: &Graph<V, E>,
            node: usize,
            visited: &mut HashSet<usize>,
            order: &mut Vec<usize>,
        ) -> Result<()> {
            visited.insert(node);
            for successor in graph.edges_out(node)? {
                if !visited.contains(&successor.tail()) {
                    dfs_walk(graph, successor.tail(), visited, order)?;
                }
            }
            order.push(node);
            Ok(())
        }

        dfs_walk(self, root, &mut visited, &mut order)?;

        Ok(order)
    }

    /// Computes the dominance frontiers for all vertices in the graph
    ///
    /// # Warning
    /// Unsure of correctness of this implementation
    pub fn compute_dominance_frontiers(
        &self,
        start_index: usize,
    ) -> Result<HashMap<usize, HashSet<usize>>> {
        let mut df: HashMap<usize, HashSet<usize>> = HashMap::new();

        for vertex in &self.vertices {
            df.insert(*vertex.0, HashSet::new());
        }

        let idoms = self.compute_immediate_dominators(start_index)?;

        for vertex in &self.vertices {
            let vertex_index: usize = *vertex.0;

            if self.edges_in[&vertex_index].len() >= 2 {
                for edge in &self.edges_in[&vertex_index] {
                    let mut runner = edge.head();
                    while idoms.contains_key(&edge.head()) && runner != idoms[&edge.head()] {
                        df.get_mut(&runner).unwrap().insert(vertex_index);
                        if !idoms.contains_key(&runner) {
                            break;
                        }
                        runner = idoms[&runner];
                    }
                }
            }
        }

        Ok(df)
    }

    pub fn compute_immediate_dominators(
        &self,
        start_index: usize,
    ) -> Result<HashMap<usize, usize>> {
        let mut idoms: HashMap<usize, usize> = HashMap::new();

        let dominators = self.compute_dominators(start_index)?;

        for vertex in &self.vertices {
            let vertex_index: usize = *vertex.0;

            let mut sdoms = dominators[&vertex_index].clone();
            sdoms.remove(&vertex_index);

            // find the strict dominator that dominates no other strict
            // dominators
            for sdom in &sdoms {
                let mut is_idom = true;
                for sdom2 in &sdoms {
                    if sdom == sdom2 {
                        continue;
                    }
                    if dominators[sdom2].contains(sdom) {
                        is_idom = false;
                        break;
                    }
                }

                if is_idom {
                    idoms.insert(vertex_index, *sdom);
                    break;
                }
            }
        }

        Ok(idoms)
    }

    /// Computes dominators for all vertices in the graph
    pub fn compute_dominators(&self, start_index: usize) -> Result<HashMap<usize, HashSet<usize>>> {
        if !self.vertices.contains_key(&start_index) {
            bail!("vertex {} not in graph", start_index);
        }

        let mut dominators: HashMap<usize, HashSet<usize>> = HashMap::new();

        // add our start vertex to our dominator set
        {
            let mut set = HashSet::new();
            set.insert(start_index);
            dominators.insert(start_index, set);
        }

        // add all successors of start vertex to queue
        let mut queue = VecDeque::new();
        for edge in &self.edges_out[&start_index] {
            queue.push_back(edge.tail());
        }

        let dag = self.compute_acyclic(start_index)?;
        let predecessors = dag.compute_predecessors()?;

        while !queue.is_empty() {
            let vertex_index: usize = queue.pop_front().unwrap();

            // are dominators for all predecessors of this block already set?
            let mut predecessors_set = true;
            for predecessor in &predecessors[&vertex_index] {
                if !dominators.contains_key(predecessor) {
                    if !queue.contains(predecessor) {
                        queue.push_back(*predecessor);
                    }
                    predecessors_set = false;
                }
            }

            if !predecessors_set {
                queue.push_back(vertex_index);
                continue;
            }

            // this vertex's dominators are the intersection of all
            // immediate predecessors' dominators, plus itself
            let mut doms: HashSet<usize> = match dag.edges_in(vertex_index).unwrap().first() {
                Some(predecessor_edge) => dominators[&predecessor_edge.head()].clone(),
                None => HashSet::new(),
            };

            for edge in &self.edges_in[&vertex_index] {
                if predecessors[&vertex_index].contains(&edge.head()) {
                    doms = &doms & &dominators[&edge.head()];
                }
            }

            doms.insert(vertex_index);

            dominators.insert(vertex_index, doms.clone());

            // add successors to the queue
            for edge in &dag.edges_out[&vertex_index] {
                if !queue.contains(&edge.tail()) {
                    queue.push_back(edge.tail());
                }
            }
        }

        Ok(dominators)
    }

    /// Computes predecessors for all vertices in the graph
    ///
    /// The resulting sets include all predecessors for each vertex in the
    /// graph, not just immediate predecessors.
    ///
    /// Given A -> B -> C, both A and B will be in the set for C.
    pub fn compute_predecessors(&self) -> Result<HashMap<usize, HashSet<usize>>> {
        let mut predecessors: HashMap<usize, HashSet<usize>> = HashMap::new();
        let mut queue: VecDeque<usize> = VecDeque::new();

        // initial population
        for vertex in &self.vertices {
            let mut preds = HashSet::new();
            for edge in self.edges_in(*vertex.0).unwrap() {
                preds.insert(edge.head());
            }
            predecessors.insert(*vertex.0, preds);
            queue.push_back(*vertex.0);
        }

        // for every vertex
        while !queue.is_empty() {
            let vertex_index = queue.pop_front().unwrap();

            // for each predecessor of this vertex
            let mut to_add: Vec<usize> = Vec::new();
            {
                let this_predecessors = &predecessors[&vertex_index];
                for predecessor in &predecessors[&vertex_index] {
                    // ensure each of this predecessor's predecessors are predecessors
                    // of this vertex
                    for pp in &predecessors[predecessor] {
                        if !this_predecessors.contains(pp) {
                            to_add.push(*pp);
                        }
                    }
                }
            }

            let this_predecessors = predecessors.get_mut(&vertex_index).unwrap();
            for predecessor in &to_add {
                this_predecessors.insert(*predecessor);
            }

            if !to_add.is_empty() {
                for successor in self.edges_out(vertex_index).unwrap() {
                    queue.push_back(successor.tail());
                }
            }
        }

        Ok(predecessors)
    }

    /// Creates an acyclic graph with NullVertex and NullEdge
    pub fn compute_acyclic(&self, start_index: usize) -> Result<Graph<NullVertex, NullEdge>> {
        let mut graph = Graph::new();
        for vertex in &self.vertices {
            graph.insert_vertex(NullVertex::new(*vertex.0))?;
        }

        let predecessors = self.compute_predecessors()?;

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_index);

        while !queue.is_empty() {
            let vertex_index = queue.pop_front().unwrap();

            visited.insert(vertex_index);

            let vertex_predecessors = &predecessors[&vertex_index];

            for edge in &self.edges_out[&vertex_index] {
                // skip edges that would create a loop
                if visited.contains(&edge.tail()) && vertex_predecessors.contains(&edge.tail()) {
                    continue;
                }
                // successors we haven't seen yet get added to the queue
                if !visited.contains(&edge.tail()) && !queue.contains(&edge.tail()) {
                    queue.push_back(edge.tail());
                }

                graph.insert_edge(NullEdge::new(edge.head(), edge.tail()))?;
            }
        }

        Ok(graph)
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
    pub fn vertex(&self, index: usize) -> Result<&V> {
        self.vertices
            .get(&index)
            .ok_or(ErrorKind::GraphVertexNotFound(index).into())
    }

    // Fetches a mutable instance of a vertex.
    pub fn vertex_mut(&mut self, index: usize) -> Result<&mut V> {
        self.vertices
            .get_mut(&index)
            .ok_or(ErrorKind::GraphVertexNotFound(index).into())
    }

    pub fn edge(&self, head: usize, tail: usize) -> Result<&E> {
        self.edges
            .get(&(head, tail))
            .ok_or(ErrorKind::GraphEdgeNotFound(head, tail).into())
    }

    pub fn edge_mut(&mut self, head: usize, tail: usize) -> Result<&mut E> {
        self.edges
            .get_mut(&(head, tail))
            .ok_or(ErrorKind::GraphEdgeNotFound(head, tail).into())
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
    pub fn edges_out(&self, index: usize) -> Result<&Vec<E>> {
        self.edges_out
            .get(&index)
            .ok_or(ErrorKind::GraphVertexNotFound(index).into())
    }

    /// Return all edges in for a vertex
    pub fn edges_in(&self, index: usize) -> Result<&Vec<E>> {
        self.edges_in
            .get(&index)
            .ok_or(ErrorKind::GraphVertexNotFound(index).into())
    }

    /// Returns a string in the graphviz format
    pub fn dot_graph(&self) -> String {
        let vertices = self
            .vertices
            .iter()
            .map(|v| {
                let label = v.1.dot_label().replace("\n", "\\l");
                format!(
                    "{} [shape=\"box\", label=\"{}\", style=\"filled\", fillcolor=\"#ffddcc\"];",
                    v.1.index(),
                    label
                )
            })
            .collect::<Vec<String>>();

        let edges = self
            .edges
            .iter()
            .map(|e| {
                let label = e.1.dot_label().replace("\n", "\\l");
                format!("{} -> {} [label=\"{}\"];", e.1.head(), e.1.tail(), label)
            })
            .collect::<Vec<String>>();

        let mut options = Vec::new();
        options.push("graph [fontname = \"Courier New\", splines=\"polyline\"]");
        options.push("node [fontname = \"Courier New\"]");
        options.push("edge [fontname = \"Courier New\"]");

        format!(
            "digraph G {{\n{}\n\n{}\n{}\n}}",
            options.join("\n"),
            vertices.join("\n"),
            edges.join("\n")
        )
    }
}
