use std::{cmp::max, collections::HashMap};

use crate::consensus::hot_stuff::utils::{View, ViewNumber};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Node not found: {0}")]
    NodeNotFound(ViewNumber),
}

pub struct Chain<T, P, S> {
    views: HashMap<ViewNumber, View<T, P, S>>,
    locked_view: ViewNumber,
    executed_view: ViewNumber,
    leaf_view: ViewNumber,
    highest_qc_view: ViewNumber,
    v_height: ViewNumber,
}

impl<T, P, S> Chain<T, P, S>
where
    T: Clone,
{
    pub fn new() -> Self {
        Self {
            views: HashMap::new(),
            locked_view: ViewNumber::default(),
            executed_view: ViewNumber::default(),
            leaf_view: ViewNumber::default(),
            highest_qc_view: ViewNumber::default(),
            v_height: ViewNumber::default(),
        }
    }

    pub fn add_node(&mut self, node: View<T, P, S>) {
        self.views.insert(node.number(), node);
    }

    pub fn update(&mut self, b3: View<T, P, S>) -> Result<Option<Vec<T>>> {
        let b2 = self.get_justified_node(&b3)?;
        let b1 = self.get_justified_node_opt(b2)?;
        let b0 = self.get_justified_node_opt(b1)?;

        let highest_qc_view = self.calc_highest_qc_view(b2);
        let locked_view = self.calc_locked_view(b1);
        let (executed_view, cmds) = self.calc_executed_view(b2, b1, b0)?;

        self.highest_qc_view = highest_qc_view;
        self.locked_view = locked_view;
        self.executed_view = executed_view;

        self.views.insert(b3.number(), b3);

        Ok(cmds)
    }

    pub fn get_node_err(&self, view: ViewNumber) -> Result<&View<T, P, S>> {
        self.views.get(&view).ok_or(Error::NodeNotFound(view))
    }

    fn get_justified_node(&self, node: &View<T, P, S>) -> Result<Option<&View<T, P, S>>> {
        match node.justify() {
            Some(qc) => Some(self.get_node_err(qc.view)).transpose(),
            None => Ok(None),
        }
    }

    fn get_justified_node_opt(
        &self,
        node: Option<&View<T, P, S>>,
    ) -> Result<Option<&View<T, P, S>>> {
        match node {
            Some(n) => self.get_justified_node(n),
            None => Ok(None),
        }
    }

    fn calc_highest_qc_view(&self, node: Option<&View<T, P, S>>) -> ViewNumber {
        max(self.highest_qc_view, node.map_or(0, |n| n.number()))
    }

    fn calc_locked_view(&self, node: Option<&View<T, P, S>>) -> ViewNumber {
        max(self.locked_view, node.map_or(0, |n| n.number()))
    }

    fn calc_executed_view(
        &self,
        b2: Option<&View<T, P, S>>,
        b1: Option<&View<T, P, S>>,
        b0: Option<&View<T, P, S>>,
    ) -> Result<(ViewNumber, Option<Vec<T>>)> {
        if let (Some(b2), Some(b1), Some(b0)) = (b2, b1, b0) {
            if b2.parent_number() == b1.number() || b1.parent_number() == b0.number() {
                let cmds = self.collect_commands(b0)?;
                return Ok((b0.number(), Some(cmds)));
            }
        }

        Ok((self.executed_view, None))
    }

    pub fn collect_commands(&self, node: &View<T, P, S>) -> Result<Vec<T>> {
        let mut cmds = Vec::new();
        let mut cur = node;

        while self.executed_view < node.number() {
            if let Some(cmd) = cur.cmd() {
                cmds.push(cmd.clone());
            }
            cur = self.get_node_err(cur.parent_number())?;
        }

        cmds.reverse();

        Ok(cmds)
    }

    pub fn locked_view_number(&self) -> ViewNumber {
        self.locked_view
    }

    pub fn executed_view_number(&self) -> ViewNumber {
        self.executed_view
    }

    pub fn leaf_view_number(&self) -> ViewNumber {
        self.leaf_view
    }

    pub fn highest_qc_view_number(&self) -> ViewNumber {
        self.highest_qc_view
    }

    pub fn v_height(&self) -> ViewNumber {
        self.v_height
    }

    pub fn locked_view(&self) -> Result<&View<T, P, S>> {
        self.get_node_err(self.locked_view)
    }

    pub fn executed_view(&self) -> Result<&View<T, P, S>> {
        self.get_node_err(self.executed_view)
    }

    pub fn leaf_view(&self) -> Result<&View<T, P, S>> {
        self.get_node_err(self.leaf_view)
    }

    pub fn highest_qc_view(&self) -> Result<&View<T, P, S>> {
        self.get_node_err(self.highest_qc_view)
    }

    pub fn is_valid_view(&self, new_view: &View<T, P, S>) -> Result<bool> {
        if new_view.number() <= self.v_height {
            return Ok(false);
        }

        if !self.extends_from_locked_view(new_view.number())?
            && new_view
                .justify()
                .is_some_and(|qc| qc.view <= self.locked_view)
        {
            return Ok(false);
        }

        Ok(true)
    }

    fn extends_from_locked_view(&self, view: ViewNumber) -> Result<bool> {
        if self.locked_view == ViewNumber::default() {
            return Ok(true);
        }

        if view == self.locked_view {
            return Ok(true);
        }

        if view < self.locked_view {
            return Ok(false);
        }

        let mut current_view = view;

        while current_view > self.locked_view {
            let current_node = self.get_node_err(current_view)?;
            let parent_view = current_node.parent_number();

            if parent_view == self.locked_view {
                return Ok(true);
            }

            if parent_view < self.locked_view {
                return Ok(false);
            }

            current_view = parent_view;
        }

        Ok(current_view == self.locked_view)
    }
}
