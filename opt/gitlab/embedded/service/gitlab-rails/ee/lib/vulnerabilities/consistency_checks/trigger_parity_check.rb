# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    class TriggerParityCheck < BaseCheck
      BATCH_SIZE = 1000
      UUID_FIX_SAMPLE_SIZE = 5
      UUID_FIX_AGE_COLUMNS = %w[finding_created finding_updated vulnerability_updated].freeze
      UUID_FIX_FLAG_COLUMNS = {
        'previous_uuid_is_new_uuid' => :previous_uuid_is_new_uuid_count,
        'multiple_findings' => :multiple_findings_count,
        'tracked_context_differs' => :tracked_context_differs_count
      }.freeze
      OCCURRENCE_ID_FIX_AGE_COLUMNS = %w[finding_created finding_updated].freeze

      # These steps copy columns from the occurrence that
      # vulnerability_reads.vulnerability_occurrence_id points at. If correcting
      # that column failed, running them would copy values from a stale finding
      # and could overwrite a correct uuid or scanner_id.
      OCCURRENCE_DEPENDENT_STEPS = %i[fix_scanner_id_mismatches fix_uuid_mismatches].freeze

      # Each fix_* method re-checks the whole project. Bound every corrective
      # UPDATE to a keyset window over vulnerability_id so no statement scans the
      # whole project and none hits the statement timeout. Coverage is preserved
      # across windows.
      #
      # The has_issues / has_merge_request probes key on vulnerability_id, not
      # vulnerability_occurrence_id. This matches the DB triggers and the
      # ingestion writer, so parity is correct under VAC where one vulnerability
      # maps to many findings. Both link tables already index vulnerability_id.
      def fix!
        errors = []
        occurrence_id_fix_failed = false

        # Shared by every sweep step, so a failure here is not a per-step
        # failure: report it once rather than five identical errors.
        begin
          reads_windows
        rescue StandardError => e
          log_step_failure(e, :reads_windows)
          raise
        end

        [
          :fix_vulnerability_occurrence_id_mismatches,
          :fix_scanner_id_mismatches,
          :fix_uuid_mismatches,
          :fix_has_issues_mismatches,
          :fix_has_merge_request_mismatches,
          :create_missing_vulnerability_reads
        ].each do |fix_method|
          next if occurrence_id_fix_failed && OCCURRENCE_DEPENDENT_STEPS.include?(fix_method)

          send(fix_method) # rubocop:disable GitlabSecurity/PublicSend -- fixed internal symbol list of private methods
        rescue StandardError => e
          log_step_failure(e, fix_method)
          errors << e
          occurrence_id_fix_failed = true if fix_method == :fix_vulnerability_occurrence_id_mismatches
        end

        # Run every step before surfacing the first failure.
        raise errors.first if errors.any?
      end

      private

      # Keep the runbook-watched 'Failed to fix vulnerability_reads' message. The
      # error text uses the LabKit-standard error_message key, as `error` is deprecated.
      def log_step_failure(error, step)
        log('Failed to fix vulnerability_reads', error_message: error.message, step: step)
        Gitlab::ErrorTracking.track_exception(error, project_id: project.id, step: step)
      end

      # Enumerate the project's vulnerability_reads in keyset windows over
      # vulnerability_id and return the inclusive [min, max] bounds of each window.
      # The bounds are computed once and memoized. All fix_* methods share them, so
      # the reads are enumerated once per fix! rather than once per method.
      # create_missing_vulnerability_reads only inserts rows, so bounds captured up
      # front stay valid for the whole run.
      def each_reads_window(&)
        reads_windows.each(&)
      end

      def reads_windows
        windows = []

        Vulnerabilities::Read.by_projects(project).each_batch(column: :vulnerability_id, of: BATCH_SIZE) do |batch|
          min_id, max_id = batch.pick(Arel.sql('MIN(vulnerability_id)'), Arel.sql('MAX(vulnerability_id)'))
          next if min_id.nil?

          windows << [min_id, max_id]
        end

        windows
      end
      strong_memoize_attr :reads_windows

      def fix_scanner_id_mismatches
        total = 0

        each_reads_window do |min_id, max_id|
          count = Vulnerabilities::Read.connection.exec_update(<<~SQL)
            UPDATE vulnerability_reads
            SET scanner_id = vo.scanner_id
            FROM vulnerability_occurrences vo
            WHERE vulnerability_reads.vulnerability_id BETWEEN #{min_id} AND #{max_id}
              AND vulnerability_reads.project_id = #{project.id}
              AND vo.id = vulnerability_reads.vulnerability_occurrence_id
              AND vulnerability_reads.scanner_id != vo.scanner_id
          SQL

          total += count
        end

        log('Fixed scanner_id mismatches', count: total) if total > 0
      end

      # The self-join on vulnerability_reads (pre) reads the row as it was
      # before this statement, so RETURNING can expose the previous uuid.
      def fix_uuid_mismatches
        stats = { count: 0, vulnerability_ids: [], report_types: Set.new, scanner_ids: Set.new }
        UUID_FIX_FLAG_COLUMNS.each_value { |key| stats[key] = 0 }

        each_reads_window do |min_id, max_id|
          Vulnerabilities::Read.connection.exec_query(<<~SQL).each { |row| add_uuid_fix_row(stats, row) }
            WITH fixed AS (
              UPDATE vulnerability_reads
              SET uuid = vo.uuid
              FROM vulnerability_occurrences vo, vulnerability_reads pre
              WHERE vulnerability_reads.vulnerability_id BETWEEN #{min_id} AND #{max_id}
                AND vulnerability_reads.project_id = #{project.id}
                AND vo.id = vulnerability_reads.vulnerability_occurrence_id
                AND vulnerability_reads.uuid != vo.uuid
                AND pre.id = vulnerability_reads.id
              RETURNING vulnerability_reads.vulnerability_id, vo.id AS finding_id, vo.report_type, vo.scanner_id,
                vo.created_at AS finding_created_at, vo.updated_at AS finding_updated_at,
                pre.uuid IS NOT DISTINCT FROM vo.new_uuid AS previous_uuid_is_new_uuid,
                vulnerability_reads.security_project_tracked_context_id
                  IS DISTINCT FROM vo.security_project_tracked_context_id AS tracked_context_differs
            )
            SELECT fixed.vulnerability_id, fixed.report_type, fixed.scanner_id,
              fixed.previous_uuid_is_new_uuid, fixed.tracked_context_differs,
              EXISTS (
                SELECT 1 FROM vulnerability_occurrences other
                WHERE other.vulnerability_id = fixed.vulnerability_id
                  AND other.id != fixed.finding_id
              ) AS multiple_findings,
              EXTRACT(EPOCH FROM now() - fixed.finding_created_at)::bigint AS finding_created,
              EXTRACT(EPOCH FROM now() - fixed.finding_updated_at)::bigint AS finding_updated,
              EXTRACT(EPOCH FROM now() - v.updated_at)::bigint AS vulnerability_updated
            FROM fixed
            LEFT JOIN vulnerabilities v ON v.id = fixed.vulnerability_id
          SQL
        end

        return if stats[:count] == 0

        scanner_ids = stats.delete(:scanner_ids)
        report_types = stats.delete(:report_types)

        log('Fixed uuid mismatches', **stats,
          report_types: report_types.to_a.compact.sort,
          scanner_ids: scanner_ids.min(UUID_FIX_SAMPLE_SIZE), scanner_count: scanner_ids.size)
      end

      def add_uuid_fix_row(stats, row)
        stats[:count] += 1
        stats[:vulnerability_ids] << row['vulnerability_id'] if stats[:vulnerability_ids].size < UUID_FIX_SAMPLE_SIZE
        stats[:report_types] << ::Enums::Vulnerability.report_types.key(row['report_type'])
        stats[:scanner_ids] << row['scanner_id']

        UUID_FIX_FLAG_COLUMNS.each { |column, key| stats[key] += 1 if row[column] }
        add_age_stats(stats, row, UUID_FIX_AGE_COLUMNS)
      end

      def add_age_stats(stats, row, columns)
        columns.each do |column|
          age = row[column]
          min_key = :"#{column}_age_min_seconds"
          max_key = :"#{column}_age_max_seconds"
          stats[min_key] = [stats[min_key], age].compact.min
          stats[max_key] = [stats[max_key], age].compact.max
        end
      end

      # uuid_differs counts fixed reads whose uuid differs from the new finding.
      # fix_uuid_mismatches repairs their uuid later in the same sweep.
      def fix_vulnerability_occurrence_id_mismatches
        stats = { count: 0, previous_null_count: 0, previous_present_count: 0, uuid_differs_count: 0 }

        each_reads_window do |min_id, max_id|
          Vulnerabilities::Read.connection.exec_query(<<~SQL).each { |row| add_occurrence_id_fix_row(stats, row) }
            WITH fixed AS (
              UPDATE vulnerability_reads
              SET vulnerability_occurrence_id = v.finding_id
              FROM vulnerabilities v, vulnerability_reads pre
              WHERE vulnerability_reads.vulnerability_id BETWEEN #{min_id} AND #{max_id}
                AND vulnerability_reads.project_id = #{project.id}
                AND vulnerability_reads.vulnerability_id = v.id
                AND (vulnerability_reads.vulnerability_occurrence_id IS NULL
                     OR vulnerability_reads.vulnerability_occurrence_id != v.finding_id)
                AND pre.id = vulnerability_reads.id
              RETURNING vulnerability_reads.vulnerability_occurrence_id, vulnerability_reads.uuid,
                pre.vulnerability_occurrence_id IS NULL AS previous_null
            )
            SELECT fixed.previous_null,
              fixed.uuid IS DISTINCT FROM vo.uuid AS uuid_differs,
              EXTRACT(EPOCH FROM now() - vo.created_at)::bigint AS finding_created,
              EXTRACT(EPOCH FROM now() - vo.updated_at)::bigint AS finding_updated
            FROM fixed
            LEFT JOIN vulnerability_occurrences vo ON vo.id = fixed.vulnerability_occurrence_id
          SQL
        end

        log('Fixed vulnerability_occurrence_id mismatches', **stats) if stats[:count] > 0
      end

      def add_occurrence_id_fix_row(stats, row)
        stats[:count] += 1
        stats[row['previous_null'] ? :previous_null_count : :previous_present_count] += 1
        stats[:uuid_differs_count] += 1 if row['uuid_differs']
        add_age_stats(stats, row, OCCURRENCE_ID_FIX_AGE_COLUMNS)
      end

      # has_issues covers external issue tracker links (for example Jira) as well
      # as GitLab issue links, because
      # VulnerabilityExternalIssueLinks::UpdateVulnerabilityRead sets it for them.
      # Counting only vulnerability_issue_links here would clear a correct flag.
      def fix_has_issues_mismatches
        total = 0

        each_reads_window do |min_id, max_id|
          count = Vulnerabilities::Read.connection.exec_update(<<~SQL)
            UPDATE vulnerability_reads
            SET has_issues = sub.expected
            FROM (
              SELECT vr.vulnerability_id,
                (
                  EXISTS (
                    SELECT 1 FROM vulnerability_issue_links vil
                    WHERE vil.vulnerability_id = vr.vulnerability_id
                  )
                  OR EXISTS (
                    SELECT 1 FROM vulnerability_external_issue_links veil
                    WHERE veil.vulnerability_id = vr.vulnerability_id
                  )
                ) AS expected
              FROM vulnerability_reads vr
              WHERE vr.vulnerability_id BETWEEN #{min_id} AND #{max_id}
                AND vr.project_id = #{project.id}
            ) sub
            WHERE vulnerability_reads.vulnerability_id = sub.vulnerability_id
              AND vulnerability_reads.has_issues != sub.expected
          SQL

          total += count
        end

        log('Fixed has_issues mismatches', count: total) if total > 0
      end

      def fix_has_merge_request_mismatches
        total = 0

        each_reads_window do |min_id, max_id|
          count = Vulnerabilities::Read.connection.exec_update(<<~SQL)
            UPDATE vulnerability_reads
            SET has_merge_request = sub.expected
            FROM (
              SELECT vr.vulnerability_id,
                EXISTS (
                  SELECT 1 FROM vulnerability_merge_request_links vmrl
                  WHERE vmrl.vulnerability_id = vr.vulnerability_id
                ) AS expected
              FROM vulnerability_reads vr
              WHERE vr.vulnerability_id BETWEEN #{min_id} AND #{max_id}
                AND vr.project_id = #{project.id}
            ) sub
            WHERE vulnerability_reads.vulnerability_id = sub.vulnerability_id
              AND vulnerability_reads.has_merge_request IS DISTINCT FROM sub.expected
          SQL

          total += count
        end

        log('Fixed has_merge_request mismatches', count: total) if total > 0
      end

      def create_missing_vulnerability_reads
        total = 0

        # Keyset over the Vulnerability PK so the NOT EXISTS anti-join is bounded
        # to one window at a time. Keep the AR-hydrating path, not a set-based
        # INSERT..SELECT. Vulnerabilities::Finding#location falls back to
        # raw_metadata when the location column is blank. A pure SQL location read
        # cannot replicate that fallback and would write NULLs for those findings.
        vulnerabilities_scope.each_batch(column: :id, of: BATCH_SIZE) do |batch|
          # Use :findings (the has_many association), not :finding (which is a memoized method, not an association)
          missing = missing_reads_relation(batch)
            .includes(:findings, :issue_links, :external_issue_links, :merge_request_links) # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check

          records = missing.to_a.filter_map do |vulnerability|
            finding = vulnerability.finding
            next unless finding

            {
              vulnerability_id: vulnerability.id,
              project_id: vulnerability.project_id,
              scanner_id: finding.scanner_id,
              report_type: vulnerability.report_type,
              severity: vulnerability.severity,
              state: vulnerability.state,
              resolved_on_default_branch: vulnerability.resolved_on_default_branch,
              uuid: finding.uuid,
              vulnerability_occurrence_id: finding.id,
              has_issues: vulnerability.issue_links.any? || vulnerability.external_issue_links.any?,
              has_merge_request: vulnerability.merge_request_links.any?,
              location_image: extract_location_image(finding),
              cluster_agent_id: extract_cluster_agent_id(finding),
              casted_cluster_agent_id: extract_casted_cluster_agent_id(finding)
            }
          end

          next if records.empty?

          result = Vulnerabilities::Read.upsert_all(
            records,
            unique_by: :index_vulnerability_reads_on_vulnerability_id,
            on_duplicate: :skip
          )

          total += result.length
        end

        log('Created missing vulnerability_reads', count: total) if total > 0
      end

      # present_on_default_branch is the predicate for "should have a
      # vulnerability_reads row". Both the DB trigger and the ingestion writer
      # create a read only for a present_on_default_branch vulnerability.
      def vulnerabilities_scope
        ::Vulnerability
          .where(project: project) # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
          .where(present_on_default_branch: true) # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
      end

      def missing_reads_relation(batch)
        batch
          .where.not( # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
            Vulnerabilities::Read
              .where('vulnerability_reads.vulnerability_id = vulnerabilities.id') # rubocop:disable CodeReuse/ActiveRecord -- bespoke consistency check
              .arel.exists
          )
      end

      def extract_location_image(finding)
        finding.location['image']
      end

      def extract_cluster_agent_id(finding)
        finding.location.dig('kubernetes_resource', 'agent_id')
      end

      def extract_casted_cluster_agent_id(finding)
        extract_cluster_agent_id(finding)&.to_i
      end
    end
  end
end
