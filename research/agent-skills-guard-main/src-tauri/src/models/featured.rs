use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Featured repositories configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturedRepositoriesConfig {
    pub version: String,
    pub last_updated: String,
    pub categories: Vec<FeaturedRepositoryCategory>,
}

/// A category of featured repositories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturedRepositoryCategory {
    pub id: String,
    pub name: HashMap<String, String>,
    pub description: HashMap<String, String>,
    pub repositories: Vec<FeaturedRepository>,
}

/// A featured repository entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturedRepository {
    pub url: String,
    pub name: String,
    pub description: HashMap<String, String>,
    pub tags: Vec<String>,
    pub featured: bool,
}
