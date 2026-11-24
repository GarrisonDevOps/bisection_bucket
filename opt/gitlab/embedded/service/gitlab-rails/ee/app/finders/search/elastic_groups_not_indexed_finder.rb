# frozen_string_literal: true

# For finding projects with repository data missing from the index
module Search
  class ElasticGroupsNotIndexedFinder
    def self.execute
      new.execute
    end

    def execute
      raise 'This cannot be run on GitLab.com' if ::Gitlab::Saas.feature_available?(:advanced_search)

      ::Gitlab::CurrentSettings.elasticsearch_enabled_groups.not_indexed_in_elasticsearch
    end
  end
end
