# frozen_string_literal: true

module Gitlab
  module Schema
    module Validation
      module Validators
        class MissingIndexes < Base
          ERROR_MESSAGE = "The index %s is missing from the database"
          REINDEX_HINT = 'An invalid index holds this name. Rebuild it with REINDEX INDEX CONCURRENTLY %s'
          RECREATE_HINT = 'An invalid index with a different definition holds this name. ' \
            'Drop it with DROP INDEX CONCURRENTLY %s, then create the index from structure.sql'

          def execute
            structure_sql.indexes.filter_map do |structure_sql_index|
              next unless index_missing?(structure_sql_index)

              build_inconsistency(self.class, structure_sql_index, nil, details: details(structure_sql_index))
            end
          end

          private

          def index_missing?(index)
            partition_index_matcher.missing?(index)
          end

          # While the invalid index holds the name, the CREATE INDEX from structure.sql fails. REINDEX keeps the
          # definition of the invalid index, so it only helps when that matches structure.sql.
          def details(index)
            invalid_index = invalid_indexes_by_key[[index.schema_name, index.name]]
            return {} unless invalid_index

            hint = invalid_index.statement == index.statement ? REINDEX_HINT : RECREATE_HINT

            { hint: format(hint, "#{index.schema_name}.#{index.name}") }
          end

          def invalid_indexes_by_key
            @invalid_indexes_by_key ||= database.invalid_indexes.each_with_object({}) do |index, map| # rubocop:disable Rails/IndexBy -- This gem does not depend on ActiveSupport.
              map[[index.schema_name, index.name]] = index
            end
          end
        end
      end
    end
  end
end
