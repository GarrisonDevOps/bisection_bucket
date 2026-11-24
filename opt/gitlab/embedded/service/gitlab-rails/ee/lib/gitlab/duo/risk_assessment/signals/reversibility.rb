# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Whether the merge request contains a database change that cannot be
        # undone by reverting it.
        #
        # Domain gates already answer "is this a migration". They cannot answer
        # "can this be rolled back", and the two are independent: adding a
        # column and dropping one are the same gate but not the same risk.
        class Reversibility < Base
          set_label N_('RiskAssessment|Reversibility')

          add_dimension :destructive, N_('RiskAssessment|Destructive database migration')

          MIGRATION_PATH = %r{\A(ee/)?db/(geo/|embedding/|ci/)?(post_)?migrate/}

          DESTRUCTIVE_OPERATIONS = %w[
            remove_column
            remove_columns
            drop_table
            drop_view
            remove_reference
            remove_belongs_to
            remove_timestamps
            truncate_tables
          ].freeze

          # Raw SQL loses the reversibility Rails would otherwise give us, so
          # match the statements that destroy data as well as the DSL calls.
          DESTRUCTIVE_SQL = /\b(DROP\s+(TABLE|COLUMN|VIEW)|TRUNCATE|DELETE\s+FROM)\b/i

          DESTRUCTIVE_CALL = /^\s*#{Regexp.union(DESTRUCTIVE_OPERATIONS)}\b/

          def available?
            return false if changed_paths.blank?
            return true if migration_paths.empty?

            migration_diffs.present?
          end

          def destructive
            destructive? ? 1.0 : 0.0
          end

          private

          def destructive?
            added_lines.any? do |line|
              line.match?(DESTRUCTIVE_CALL) || line.match?(DESTRUCTIVE_SQL)
            end
          end

          def added_lines
            migration_diffs.flat_map do |diff_file|
              diff_file.utf8_diff.each_line.filter_map do |line|
                line[1..].to_s.chomp if line.start_with?('+') && !line.start_with?('+++')
              end
            end
          end

          def migration_paths
            changed_paths.select { |path| path.match?(MIGRATION_PATH) }
          end
          strong_memoize_attr :migration_paths

          # Read from merge_request_diff_files rather than Gitaly, and only for
          # the migration paths, so the content read stays bounded.
          def migration_diffs
            return [] if migration_paths.empty?

            diff = merge_request.merge_request_diff
            return [] unless diff&.persisted?

            diff.merge_request_diff_files.by_paths(migration_paths).to_a
          end
          strong_memoize_attr :migration_diffs
        end
      end
    end
  end
end
