# frozen_string_literal: true

module Search
  module Elastic
    module Sorts
      class Base
        SORT_MAPPINGS = {
          created_at_asc: { created_at: { order: 'asc' } },
          created_at_desc: { created_at: { order: 'desc' } },
          updated_at_asc: { updated_at: { order: 'asc' } },
          updated_at_desc: { updated_at: { order: 'desc' } }
        }.freeze

        # Sort keys that cannot be answered by the index until an advanced search migration has
        # finished, as `{ sort_key => migration_name }`. Subclasses override this constant.
        MIGRATION_GATED_SORT_KEYS = {}.freeze

        # Substituted for a gated sort key. Must be a key every subclass' SORT_MAPPINGS defines, so
        # `sort` is always populated: Pagination reads `query_hash[:sort]` unconditionally
        # (ee/lib/search/elastic/pagination.rb:155).
        FALLBACK_SORT_KEY = :created_at_desc

        class << self
          def sort_by(query_hash:, options:)
            sort_hash = build_sort(options[:order_by], options[:sort])
            query_hash.merge(sort: sort_hash)
          end

          # Whether the index can answer this sort yet. Callers that can route the query elsewhere
          # (the advanced finders, which fall back to PostgreSQL) should check this before choosing
          # Elasticsearch; #sort_by degrades to FALLBACK_SORT_KEY for callers that cannot.
          def sort_available?(order_by, sort)
            sort_key_available?(::Search::SortOptions.sort_and_direction(order_by, sort))
          end

          private

          def sort_key_available?(sort_key)
            migration = self::MIGRATION_GATED_SORT_KEYS[sort_key]
            return true unless migration

            ::Elastic::DataMigrationService.migration_has_finished?(migration)
          end

          def build_sort(order_by, sort)
            sort_and_direction = ::Search::SortOptions.sort_and_direction(order_by, sort)

            unless sort_key_available?(sort_and_direction)
              # Callers reaching here could not re-route (unlike the advanced finders, which check
              # sort_available? and use PostgreSQL instead), so the request is answered in a
              # different order than it asked for. Log it: a silent substitution is
              # indistinguishable from a working sort in production.
              # LabKit defines no standard field for a sort key, so the three specifics go under
              # ADDITIONAL_DETAILS rather than as ad hoc top-level keys.
              ::Gitlab::AppLogger.warn(
                Labkit::Fields::LOG_MESSAGE => 'search sort key unavailable, falling back',
                Labkit::Fields::CLASS_NAME => name,
                Labkit::Fields::ADDITIONAL_DETAILS => {
                  requested_sort_key: sort_and_direction,
                  fallback_sort_key: self::FALLBACK_SORT_KEY,
                  pending_migration: self::MIGRATION_GATED_SORT_KEYS[sort_and_direction]
                }
              )

              sort_and_direction = self::FALLBACK_SORT_KEY
            end

            self::SORT_MAPPINGS.fetch(sort_and_direction, {})
          end
        end
      end
    end
  end
end
