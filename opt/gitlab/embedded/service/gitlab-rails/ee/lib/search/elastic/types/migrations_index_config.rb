# frozen_string_literal: true

module Search
  module Elastic
    module Types
      class MigrationsIndexConfig
        class << self
          def index_name
            Search::Elastic::References::MigrationsIndexConfig.index
          end

          def mappings
            {
              properties: {
                completed: { type: 'boolean' },
                state: { type: 'object' },
                started_at: { type: 'date' },
                completed_at: { type: 'date' },
                name: { type: 'keyword' }
              }
            }
          end

          def settings
            { number_of_shards: 1 }
          end

          # Cannot be reindexed until delete_legacy_migrations_index migration finishes
          def ready?
            ::Elastic::DataMigrationService.migration_has_finished?(:delete_legacy_migrations_index)
          end
        end
      end
    end
  end
end
