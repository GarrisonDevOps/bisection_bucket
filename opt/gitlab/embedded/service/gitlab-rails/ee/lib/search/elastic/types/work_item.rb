# frozen_string_literal: true

module Search
  module Elastic
    module Types
      class WorkItem
        class << self
          def index_name
            Search::Elastic::References::WorkItem.index
          end

          def target
            ::WorkItem
          end

          def mappings
            {
              dynamic: 'strict',
              properties: base_mappings
            }
          end

          def settings
            ::Elastic::Latest::Config.settings.to_hash.deep_merge(
              index: ::Elastic::Latest::Config.separate_index_specific_settings(index_name)
            )
          end

          private

          def base_mappings
            {
              type: { type: 'keyword' },
              id: { type: 'long' },
              iid: { type: 'integer' },
              title: {
                type: 'text',
                index_options: 'positions',
                analyzer: :title_analyzer,
                fields: {
                  # Sortable sub-field. `lower_case_normalizer` makes the sort key the lowercased
                  # title compared in code point order, which matches `lower(title)` on the
                  # PostgreSQL path (app/models/concerns/sortable_title.rb:6-7) for ASCII-only
                  # titles under a byte-ordered (`C`) collation. On non-ASCII titles the two
                  # paths can disagree under any collation, so basic and advanced search are not
                  # guaranteed to return the same order for them. Measured on PostgreSQL 17.8 and
                  # Elasticsearch 9.4.4, sorting a title starting U+00C1 against one starting
                  # U+00E0: under `C`, PostgreSQL's `lower()` leaves U+00C1 uppercase while
                  # Lucene's `lowercase` filter folds it to U+00E1, so PostgreSQL puts the U+00C1
                  # title first and Elasticsearch puts it second. Under `en_US.utf8` PostgreSQL
                  # orders a U+00E1 title before a U+00E0 one and Elasticsearch does the reverse.
                  # `ignore_above` is 1024: titles are capped at 255 characters by
                  # Issuable::TITLE_LENGTH_MAX, so nothing reachable through the model is dropped,
                  # and 1024 characters stays far below Lucene's 32766-byte term limit.
                  # A longer title is still indexed and still returned; it simply has no value for
                  # this sub-field, which forward paging places last in both sort directions
                  # (Search::Elastic::Pagination#order passes missing: MISSING_LAST; #reverse_order
                  # flips it to MISSING_FIRST so a backward page can cross that boundary).
                  keyword: { type: 'keyword', normalizer: 'lower_case_normalizer', ignore_above: 1024 }
                }
              },
              description: { type: 'text', index_options: 'positions', analyzer: :code_analyzer },
              namespace_id: { type: 'long' },
              root_namespace_id: { type: 'long' },
              created_at: { type: 'date' },
              updated_at: { type: 'date' },
              due_date: { type: 'date' },
              state: { type: 'keyword' },
              project_id: { type: 'long' },
              routing: { type: 'text' },
              author_id: { type: 'long' },
              confidential: { type: 'boolean' },
              hidden: { type: 'boolean' },
              archived: { type: 'boolean' },
              assignee_id: { type: 'long' },
              project_visibility_level: { type: 'short' },
              namespace_visibility_level: { type: 'short' },
              issues_access_level: { type: 'short' },
              upvotes: { type: 'integer' },
              traversal_ids: { type: 'keyword' },
              organization_id: { type: 'long' },
              organization_traversal_ids: { type: 'keyword' },
              label_ids: { type: 'keyword' },
              hashed_root_namespace_id: { type: 'integer' },
              work_item_type_id: { type: 'long' },
              schema_version: { type: 'short' },
              milestone_title: { type: 'keyword' },
              milestone_id: { type: 'long' },
              milestone_start_date: { type: 'date' },
              milestone_due_date: { type: 'date' },
              milestone_state: { type: 'keyword' },
              closed_at: { type: 'date' },
              weight: { type: 'integer' },
              health_status: { type: 'short' },
              label_names: { type: 'keyword' }
            }
          end
        end
      end
    end
  end
end
