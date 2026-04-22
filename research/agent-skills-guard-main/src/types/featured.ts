/**
 * Featured repositories configuration types
 */

export interface FeaturedRepositoriesConfig {
  version: string;
  last_updated: string;
  categories: FeaturedRepositoryCategory[];
}

export interface FeaturedRepositoryCategory {
  id: string;
  name: {
    en: string;
    zh: string;
  };
  description: {
    en: string;
    zh: string;
  };
  repositories: FeaturedRepository[];
}

export interface FeaturedRepository {
  url: string;
  name: string;
  description: {
    en: string;
    zh: string;
  };
  tags: string[];
  featured: boolean; // Whether to feature on the homepage
}
