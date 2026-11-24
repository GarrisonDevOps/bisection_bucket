# frozen_string_literal: true

module Search
  module Elastic
    module SbomOccurrenceRefIndexHelper
      class << self
        def indexing_allowed?
          ::Gitlab::CurrentSettings.elasticsearch_indexing? &&
            ::Elastic::DataMigrationService.migration_has_finished?(:create_sbom_occurrence_refs_index)
        end

        # Reads need `elasticsearch_search?` on top of indexing: an instance can keep the
        # index current while search is switched off.
        def advanced_dependency_management_allowed?
          indexing_allowed? && ::Gitlab::CurrentSettings.elasticsearch_search?
        end
      end
    end
  end
end
