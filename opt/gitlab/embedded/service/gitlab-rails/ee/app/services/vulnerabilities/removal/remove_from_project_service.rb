# frozen_string_literal: true

module Vulnerabilities
  module Removal
    # This class is responsible for removing the vulnerability records
    # associated with the given project.
    #
    # We are not deleting the `scanner` records because they are associated
    # with the `security_findings` records and deleting them scan cause
    # cascading delete on millions of `security_findings` records.
    class RemoveFromProjectService
      class BatchRemoval
        TASKS_SCOPED_TO_FINDINGS = [
          Tasks::DeleteFindingEvidences,
          Tasks::DeleteFindingFlags,
          Tasks::DeleteFindingIdentifiers,
          Tasks::DeleteFindingLinks,
          Tasks::DeleteFindingRemediations,
          Tasks::DeleteFindingSignatures
        ].freeze

        TASKS_SCOPED_TO_VULNERABILITIES = [
          Tasks::DeleteVulnerabilityExternalIssueLinks,
          Tasks::DeleteVulnerabilityIssueLinks,
          Tasks::DeleteVulnerabilityMergeRequestLinks,
          Tasks::DeleteVulnerabilityReads,
          Tasks::DeleteVulnerabilitySeverityOverrides,
          Tasks::DeleteVulnerabilityStateTransitions,
          Tasks::DeleteVulnerabilityUserMentions
        ].freeze

        def initialize(project, batch, update_counts:, backup: nil)
          @project = project
          @batch = batch
          @update_counts = update_counts
          @backup = backup
        end

        def execute
          return false if batch_size == 0

          Vulnerability.feature_flagged_transaction_for(project) do
            es_references = build_es_references

            delete_resources_by_findings
            delete_resources_by_vulnerabilities

            # When we delete `vulnerabilities` first, the foreign key nullifies the `finding#vulnerability_id` column
            # which later causes exception while creating the backup records for the findings.
            # When we delete the `findings` first, the other foreign key cascades the delete to vulnerability records
            # which later results in no backups for the vulnerability records because the delete query doesn't delete
            # anything, therefore, returns no rows.
            #
            # In this line, we load finding data into memory before firing any delete query so that the returned rows
            # can later be used while creating the backup records.
            finding_rows = get_finding_rows if backup

            delete_vulnerabilities
            delete_findings(finding_rows)

            update_project_vulnerabilities_count if update_counts

            Vulnerability.current_transaction.after_commit do
              ::Elastic::ProcessBookkeepingService.track!(*es_references)
            end
          end

          true
        end

        private

        attr_reader :project, :batch, :update_counts, :backup

        delegate :connection, :sanitize_sql_array, to: Vulnerability, private: true

        def delete_resources_by_findings
          TASKS_SCOPED_TO_FINDINGS.each { |task| task.new(finding_ids, backup).execute }
        end

        def delete_resources_by_vulnerabilities
          TASKS_SCOPED_TO_VULNERABILITIES.each { |task| task.new(vulnerability_ids, backup).execute }
        end

        def delete_vulnerabilities
          deleted_rows = Vulnerability.id_in(vulnerability_ids).delete_all_returning

          return unless backup

          Vulnerabilities::Removal::BackupService.execute(
            Vulnerabilities::Backups::Vulnerability,
            backup,
            deleted_rows,
            extra: { traversal_ids: project.namespace.traversal_ids }
          )
        end

        def delete_findings(finding_rows)
          Vulnerabilities::Finding.id_in(finding_ids).delete_all

          return unless backup

          Vulnerabilities::Removal::BackupService.execute(
            Vulnerabilities::Backups::Finding,
            backup,
            finding_rows
          )
        end

        def get_finding_rows
          connection.execute(select_findings_query).to_a
        end

        def select_findings_query
          sanitize_sql_array(["SELECT * FROM vulnerability_occurrences WHERE id IN (?)", finding_ids])
        end

        def build_es_references
          return [] unless ::Search::Elastic::VulnerabilityIndexHelper.indexing_allowed?

          ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new([project.namespace]).execute

          records = Vulnerabilities::Read.by_vulnerabilities(vulnerability_ids)

          records.each { |record| record.association(:project).target = project }
          # flat_map is temporary to support Vulnerabilities::Read - elastic_reference returning an array
          # when vulnerability_read_es_dual_write is enabled. Change to map when the feature flag is removed.
          records.select(&:maintaining_elasticsearch?).flat_map(&:elastic_reference)
        end

        def update_project_vulnerabilities_count
          project.security_statistics.decrease_vulnerability_counter!(batch_size)
        end

        def batch_size
          vulnerability_ids.length
        end

        def vulnerability_ids
          @vulnerability_ids ||= batch_attributes.map(&:first)
        end

        def finding_ids
          @finding_ids ||= batch_attributes.map(&:second)
        end

        def batch_attributes
          @batch_attributes ||= batch.pluck(:id, :finding_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- This is a very specific usage
        end
      end

      BATCH_SIZE = 100

      def initialize(project, params)
        @project = project
        @resolved_on_default_branch = params[:resolved_on_default_branch]
      end

      def execute
        delete_vulnerabilities_on_default_branch
        delete_vulnerabilities_not_present_on_default_branch
        update_vulnerability_statistics
        delete_feedback_records
        delete_historical_statistics
        reset_has_vulnerabilities
      end

      private

      attr_reader :project, :resolved_on_default_branch

      # Vulnerabilities with `present_on_default_branch` attribute as `true` are associated
      # with `vulnerability_reads`, therefore, iterating over `vulnerability_reads` table
      # is fine.
      def delete_vulnerabilities_on_default_branch
        loop do
          vulnerability_ids = vulnerability_reads.limit(BATCH_SIZE).pluck_primary_key
          vulnerabilities = Vulnerability.id_in(vulnerability_ids)
          batch_removal = BatchRemoval.new(project, vulnerabilities, update_counts: true)

          break unless batch_removal.execute
        end
      end

      # This makes sure that we delete vulnerabilities that are not `present_on_default_branch`.
      def delete_vulnerabilities_not_present_on_default_branch
        return unless full_cleanup?

        loop do
          batch = vulnerabilities.limit(BATCH_SIZE)
          batch_removal = BatchRemoval.new(project, batch, update_counts: false)

          break unless batch_removal.execute
        end
      end

      def vulnerability_reads
        return Vulnerabilities::Read.by_projects(project) if full_cleanup?

        Vulnerabilities::Read.by_projects(project).with_resolution(resolved_on_default_branch)
      end

      def vulnerabilities
        Vulnerability.with_project(project)
      end

      def update_vulnerability_statistics
        Vulnerabilities::Statistics::AdjustmentWorker.perform_async([project.id])
      end

      # Do we really need to delete these records? The feedback model has already been
      # deprecated and the model will be removed soon.
      def delete_feedback_records
        return unless full_cleanup?

        loop { break if project.vulnerability_feedback.limit(BATCH_SIZE).delete_all == 0 }
      end

      def delete_historical_statistics
        return unless full_cleanup?

        loop { break if project.vulnerability_historical_statistics.limit(BATCH_SIZE).delete_all == 0 }
      end

      def full_cleanup?
        resolved_on_default_branch.nil?
      end

      def reset_has_vulnerabilities
        project.project_setting.update!(has_vulnerabilities: vulnerabilities.exists?)
      end
    end
  end
end
