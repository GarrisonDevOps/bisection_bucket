# frozen_string_literal: true

namespace :gitlab do
  namespace :db do
    namespace :open_ended_columns do
      desc 'GitLab | DB | Regenerate the open-ended columns allowlist'
      task generate_allowlist: %i[environment] do
        path = Rails.root.join('spec/support/database/open-ended-columns-allowlist.yml')

        header = <<~HEADER
          # Columns of open-ended (unbounded-width) types that exist in the schema
          # without a size-enforcing CHECK constraint.
          #
          # Consumed by spec/db/open_ended_columns_spec.rb. Every "table.column"
          # listed here is grandfathered in: it predates the open-ended column
          # guard. This list must only shrink: once a column gains a size limit
          # (add_text_limit), remove it from this file. New open-ended columns must
          # be given a limit rather than being added here, except array columns,
          # whose per-element size PostgreSQL cannot bound.
          #
          # Follows the same grandfathering pattern as
          # spec/support/database/retention-policy-missing-allowlist.yml.
          #
          # Regenerate the allowlist with:
          #   bundle exec rake gitlab:db:open_ended_columns:generate_allowlist
        HEADER

        identifiers = Gitlab::Database::OpenEndedColumns.unbounded_identifiers

        File.write(path, "#{header}#{identifiers.to_yaml}")

        puts "Wrote #{identifiers.size} columns to #{path.relative_path_from(Rails.root)}."
      end
    end
  end
end
