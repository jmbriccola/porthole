//! The firewalld backend. Implemented in the next task.

use super::{BackendHealth, BackendId, FirewallBackend, RuleHandle};
use crate::command::CommandRunner;
use crate::error::{Error, Result};
use crate::model::OpenRequest;

pub struct Firewalld<'a> {
    #[allow(dead_code)]
    runner: &'a dyn CommandRunner,
}

impl<'a> Firewalld<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Firewalld { runner }
    }
}

impl FirewallBackend for Firewalld<'_> {
    fn id(&self) -> BackendId {
        BackendId::Firewalld
    }
    fn open(&self, _req: &OpenRequest) -> Result<RuleHandle> {
        Err(Error::Unexpected("not implemented".into()))
    }
    fn close(&self, _handle: &RuleHandle) -> Result<()> {
        Err(Error::Unexpected("not implemented".into()))
    }
    fn list_managed(&self) -> Result<Vec<RuleHandle>> {
        Err(Error::Unexpected("not implemented".into()))
    }
    fn health(&self) -> Result<BackendHealth> {
        Err(Error::Unexpected("not implemented".into()))
    }
}
