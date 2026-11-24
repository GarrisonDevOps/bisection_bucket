# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IngestVulnerabilities
        # Applies severity overrides of existing vulnerability records
        # by using a single database query.
        class ApplySeverityOverrides < AbstractTask
          UPDATE_SQL_STATEMENT = <<~SQL
            WITH latest_severity_overrides AS (
              SELECT
                  vulnerability_id,
                  new_severity
              FROM
                  vulnerabilities,
                  LATERAL (
                      SELECT
                          vulnerability_id,
                          new_severity
                      FROM
                          vulnerability_severity_overrides
                      WHERE
                          vulnerability_id = vulnerabilities.id
                      ORDER BY
                          id DESC
                      LIMIT 1) AS latest_severity_override
              WHERE
                  vulnerabilities.id IN (%{vulnerability_ids}))
            UPDATE
                vulnerabilities
            SET
                severity = latest_severity_overrides.new_severity
            FROM
                latest_severity_overrides
            WHERE
                vulnerabilities.id = latest_severity_overrides.vulnerability_id
          SQL

          def execute
            return unless vulnerability_ids.present?

            connection.execute(update_sql)

            finding_maps
          end

          private

          delegate :connection, to: ::Vulnerabilities::SeverityOverride, private: true

          def vulnerability_ids
            @vulnerability_ids ||= finding_maps
              .map(&:vulnerability_id)
              .map { |id| connection.quote(id) }
          end

          def update_sql
            format(
              UPDATE_SQL_STATEMENT,
              vulnerability_ids: vulnerability_ids.join(', ')
            )
          end
        end
      end
    end
  end
end
