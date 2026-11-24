# frozen_string_literal: true

module Search
  module Elastic
    module References
      class MigrationsIndexConfig < Reference
        INDEX_NAME = 'search-migrations'

        def self.index
          environment_specific_index_name(INDEX_NAME)
        end

        def self.model_klass
          # No ActiveRecord model backs this index - it tracks Elasticsearch migration state.
          # Settings are managed via ::Elastic::IndexSetting instead.
          nil
        end
      end
    end
  end
end
