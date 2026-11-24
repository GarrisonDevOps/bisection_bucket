# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    # TEMPORARY CHECK: This check backfills NULL vulnerability_occurrence_id values
    # in vulnerability_issue_links before VAC (Vulnerabilities Across Contexts) is enabled.
    #
    # While VAC is disabled, we can safely derive vulnerability_occurrence_id from
    # vulnerabilities.finding_id (1:1 relationship). Once VAC is enabled, this relationship
    # becomes 1:many and we can no longer safely derive it.
    #
    # This check:
    # - Only runs when VAC feature flag is OFF
    # - Only updates NULL values (never overwrites existing)
    # - Should be removed once NOT NULL constraints are added to the column
    #
    # Related issues:
    # - https://gitlab.com/gitlab-org/gitlab/-/issues/596474 (this check)
    # - https://gitlab.com/gitlab-org/gitlab/-/issues/596476 (NOT NULL constraint)
    # - https://gitlab.com/gitlab-org/gitlab/-/issues/596477 (removal)
    class BackfillIssueLinkOccurrenceIdCheck < BaseCheck
      BATCH_SIZE = 1000

      def consistent?
        return true if vac_enabled?

        !null_occurrence_ids_exist?
      end

      def fix!
        return if vac_enabled?

        total = 0

        null_occurrence_id_relation.each_batch(of: BATCH_SIZE) do |batch|
          count = Vulnerabilities::IssueLink.connection.exec_update(<<~SQL)
            UPDATE vulnerability_issue_links
            SET vulnerability_occurrence_id = v.finding_id
            FROM vulnerabilities v
            WHERE vulnerability_issue_links.id IN (#{batch.select(:id).to_sql})
              AND vulnerability_issue_links.vulnerability_id = v.id
              AND vulnerability_issue_links.vulnerability_occurrence_id IS NULL
              AND v.finding_id IS NOT NULL
          SQL

          total += count
        end

        log('Backfilled vulnerability_occurrence_id in vulnerability_issue_links', count: total) if total > 0
      end

      private

      def vac_enabled?
        Security::VAC.enabled?(project)
      end

      def null_occurrence_ids_exist?
        null_occurrence_id_relation.exists?
      end

      # rubocop:disable CodeReuse/ActiveRecord -- temporary backfill check
      def null_occurrence_id_relation
        Vulnerabilities::IssueLink
          .where(vulnerability_occurrence_id: nil)
          .joins(:vulnerability)
          .where(vulnerabilities: { project_id: project.id })
          .where.not(vulnerabilities: { finding_id: nil })
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
