# frozen_string_literal: true

module Search
  module Elastic
    module Types
      class Group
        class << self
          def index_name
            Search::Elastic::References::Group.index
          end

          def target
            ::Group
          end

          def mappings
            {
              dynamic: 'strict',
              properties: base_mappings
            }
          end

          def settings
            base_settings
          end

          private

          def base_mappings
            {
              type: { type: 'keyword' },
              schema_version: { type: 'short' },
              id: { type: 'long' },
              name: { type: 'text', index_options: 'positions', analyzer: 'my_ngram_analyzer' },
              path: { type: 'text', index_options: 'positions' },
              full_name: { type: 'text', index_options: 'positions', analyzer: 'my_ngram_analyzer' },
              full_path: { type: 'text', index_options: 'positions' },
              description: { type: 'text', index_options: 'positions' },
              parent_id: { type: 'long' },
              traversal_ids: { type: 'keyword' },
              visibility_level: { type: 'short' },
              created_at: { type: 'date' },
              updated_at: { type: 'date' },
              archived: { type: 'boolean' },
              active: { type: 'boolean' },
              organization_id: { type: 'long' },
              organization_traversal_ids: { type: 'keyword' }
            }
          end

          def base_settings
            ::Elastic::Latest::Config.settings.to_hash.deep_merge(
              index: ::Elastic::Latest::Config.separate_index_specific_settings(index_name)
            )
          end
        end
      end
    end
  end
end
