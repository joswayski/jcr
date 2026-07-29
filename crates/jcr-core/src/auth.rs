use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessAction {
    Pull,
    Push,
    Delete,
    Admin,
}

impl fmt::Display for AccessAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Delete => "delete",
            Self::Admin => "admin",
        })
    }
}

impl FromStr for AccessAction {
    type Err = ScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pull" => Ok(Self::Pull),
            "push" => Ok(Self::Push),
            "delete" => Ok(Self::Delete),
            "admin" => Ok(Self::Admin),
            _ => Err(ScopeError::UnknownAction(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepositoryScope {
    pub repository: String,
    pub actions: BTreeSet<AccessAction>,
}

impl RepositoryScope {
    pub fn new(
        repository: impl Into<String>,
        actions: impl IntoIterator<Item = AccessAction>,
    ) -> Self {
        Self {
            repository: repository.into(),
            actions: actions.into_iter().collect(),
        }
    }

    pub fn permits(&self, repository: &str, action: AccessAction) -> bool {
        self.repository == repository
            && (self.actions.contains(&action) || self.actions.contains(&AccessAction::Admin))
    }
}

impl fmt::Display for RepositoryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let actions = self
            .actions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        write!(formatter, "repository:{}:{actions}", self.repository)
    }
}

impl FromStr for RepositoryScope {
    type Err = ScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut pieces = value.splitn(3, ':');
        if pieces.next() != Some("repository") {
            return Err(ScopeError::UnsupportedResource);
        }

        let repository = pieces.next().ok_or(ScopeError::InvalidFormat)?;
        let actions = pieces.next().ok_or(ScopeError::InvalidFormat)?;
        if repository.is_empty() {
            return Err(ScopeError::InvalidFormat);
        }

        let actions = actions
            .split(',')
            .filter(|action| !action.is_empty())
            .map(AccessAction::from_str)
            .collect::<Result<BTreeSet<_>, _>>()?;

        Ok(Self {
            repository: repository.to_owned(),
            actions,
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ScopeError {
    #[error("scope must use repository:<name>:<actions>")]
    InvalidFormat,
    #[error("only repository scopes are supported")]
    UnsupportedResource,
    #[error("unknown repository action '{0}'")]
    UnknownAction(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repository_scope() {
        let scope: RepositoryScope = "repository:alice/app:pull,push".parse().unwrap();
        assert!(scope.permits("alice/app", AccessAction::Pull));
        assert!(scope.permits("alice/app", AccessAction::Push));
        assert!(!scope.permits("alice/other", AccessAction::Pull));
    }

    #[test]
    fn admin_implies_repository_actions() {
        let scope = RepositoryScope::new("alice/app", [AccessAction::Admin]);
        assert!(scope.permits("alice/app", AccessAction::Delete));
    }
}
