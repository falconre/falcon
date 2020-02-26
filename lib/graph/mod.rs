//! Implements a directed graph.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

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
        if let Some(successors) = self.successors.get(&index) {
            for successor in successors {
                edges.push((index, *successor));
            }
        };
        if let Some(predecessors) = self.predecessors.get(&index) {
            for predecessor in predecessors {
                edges.push((*predecessor, index));
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

    /// Removes an edge
    pub fn remove_edge(&mut self, head: usize, tail: usize) -> Result<()> {
        if !self.edges.contains_key(&(head, tail)) {
            bail!("edge does not exist");
        }

        self.edges.remove(&(head, tail));

        self.predecessors.get_mut(&tail).unwrap().remove(&head);

        self.successors.get_mut(&head).unwrap().remove(&tail);

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
        self.successors.insert(v.index(), BTreeSet::new());
        self.predecessors.insert(v.index(), BTreeSet::new());
        Ok(())
    }

    /// Inserts an edge into the graph.
    /// # Errors
    /// Error if the edge already exists by indices.
    pub fn insert_edge(&mut self, edge: E) -> Result<()> {
        if self.edges.contains_key(&(edge.head(), edge.tail())) {
            return Err("duplicate edge".into());
        }
        if !self.vertices.contains_key(&edge.head()) {
            return Err(ErrorKind::GraphVertexNotFound(edge.head()).into());
        }
        if !self.vertices.contains_key(&edge.tail()) {
            return Err(ErrorKind::GraphVertexNotFound(edge.tail()).into());
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
    pub fn successors(&self, index: usize) -> Result<Vec<&V>> {
        if !self.vertices.contains_key(&index) {
            bail!(
                "Vertex {} does not exist and therefor has no successors",
                index
            );
        }

        let vertices = &self.successors[&index];

        Ok(vertices.iter().fold(Vec::new(), |mut v, index| {
            v.push(self.vertices.get(index).unwrap());
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

        let vertices = &self.predecessors[&index];

        Ok(vertices.iter().fold(Vec::new(), |mut v, index| {
            v.push(self.vertices.get(index).unwrap());
            v
        }))
    }

    /// Returns the indices of all immediate successors of a vertex from the graph.
    pub fn successor_indices(&self, index: usize) -> Result<Vec<usize>> {
        if !self.vertices.contains_key(&index) {
            bail!(
                "Vertex {} does not exist and therefor has no successors",
                index
            );
        }

        Ok(self.successors[&index].iter().cloned().collect())
    }

    /// Returns the indices of all immediate predecessors of a vertex from the graph.
    pub fn predecessor_indices(&self, index: usize) -> Result<Vec<usize>> {
        if !self.vertices.contains_key(&index) {
            bail!(
                "Vertex {} does not exist and therefor has no predecessors",
                index
            );
        }

        Ok(self.predecessors[&index].iter().cloned().collect())
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
    ) -> Result<HashMap<usize, HashSet<usize>>> {
        let mut df: HashMap<usize, HashSet<usize>> = HashMap::new();

        for vertex in &self.vertices {
            df.insert(*vertex.0, HashSet::new());
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
        for successor in &self.successors[&start_index] {
            queue.push_back(*successor);
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
            let mut doms: HashSet<usize> = match dag.predecessors[&vertex_index].iter().next() {
                Some(predecessor) => dominators[predecessor].clone(),
                None => HashSet::new(),
            };

            for predecessor in &self.predecessors[&vertex_index] {
                if predecessors[&vertex_index].contains(predecessor) {
                    doms = &doms & &dominators[predecessor];
                }
            }

            doms.insert(vertex_index);

            dominators.insert(vertex_index, doms.clone());

            // add successors to the queue
            for successor in &dag.successors[&vertex_index] {
                if !queue.contains(successor) {
                    queue.push_back(*successor);
                }
            }
        }

        Ok(dominators)
    }

    /// Creates a dominator tree with NullVertex and NullEdge
    pub fn compute_dominator_tree(
        &self,
        start_index: usize,
    ) -> Result<Graph<NullVertex, NullEdge>> {
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
    pub fn compute_predecessors(&self) -> Result<HashMap<usize, HashSet<usize>>> {
        let mut predecessors: HashMap<usize, HashSet<usize>> = HashMap::new();
        let mut queue: VecDeque<usize> = VecDeque::new();

        // initial population
        for vertex in &self.vertices {
            let mut preds = HashSet::new();
            for predecessor in &self.predecessors[vertex.0] {
                preds.insert(*predecessor);
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
                for successor in &self.successors[&vertex_index] {
                    queue.push_back(*successor);
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

    /// Computes the topological ordering of all vertices in the graph
    pub fn compute_topological_ordering(&self, root: usize) -> Result<Vec<usize>> {
        let mut permanent_marks: HashSet<usize> = HashSet::new();
        let mut temporary_marks: HashSet<usize> = HashSet::new();
        let mut order: Vec<usize> = Vec::new();

        fn dfs_walk<V: Vertex, E: Edge>(
            graph: &Graph<V, E>,
            node: usize,
            permanent_marks: &mut HashSet<usize>,
            temporary_marks: &mut HashSet<usize>,
            order: &mut Vec<usize>,
        ) -> Result<()> {
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

        dfs_walk(
            self,
            root,
            &mut permanent_marks,
            &mut temporary_marks,
            &mut order,
        )?;

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
    pub fn edges_out(&self, index: usize) -> Result<Vec<&E>> {
        self.successors
            .get(&index)
            .map(|succs| {
                succs
                    .iter()
                    .map(|succ| &self.edges[&(index, *succ)])
                    .collect()
            })
            .ok_or(ErrorKind::GraphVertexNotFound(index).into())
    }

    /// Return all edges in for a vertex
    pub fn edges_in(&self, index: usize) -> Result<Vec<&E>> {
        self.predecessors
            .get(&index)
            .map(|preds| {
                preds
                    .iter()
                    .map(|pred| &self.edges[&(*pred, index)])
                    .collect()
            })
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
    fn test_immediate_dominators() {
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
        assert!(graph.compute_topological_ordering(1).is_err());
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
            graph.compute_topological_ordering(1).unwrap(),
            vec![1, 2, 5, 6, 3, 7, 4]
        );
    }
}
