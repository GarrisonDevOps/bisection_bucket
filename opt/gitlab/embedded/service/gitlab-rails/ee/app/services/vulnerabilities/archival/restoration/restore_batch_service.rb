# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      class RestoreBatchService
        BACKUPS_SCOPED_TO_VULNERABILITIES = [
          Vulnerabilities::Backups::VulnerabilityExternalIssueLink,
          Vulnerabilities::Backups::VulnerabilityIssueLink,
          Vulnerabilities::Backups::VulnerabilityMergeRequestLink,
          Vulnerabilities::Backups::VulnerabilityRead,
          Vulnerabilities::Backups::VulnerabilitySeverityOverride,
          Vulnerabilities::Backups::VulnerabilityStateTransition,
          Vulnerabilities::Backups::VulnerabilityUserMention
        ].freeze

        BACKUPS_SCOPED_TO_FINDINGS = [
          Vulnerabilities::Backups::FindingEvidence,
          Vulnerabilities::Backups::FindingFlag,
          Vulnerabilities::Backups::FindingIdentifier,
          Vulnerabilities::Backups::FindingLink,
          Vulnerabilities::Backups::FindingRemediation,
          Vulnerabilities::Backups::FindingSignature
        ].freeze

        def self.execute(...)
          new(...).execute
        end

        def initialize(vulnerability_backups)
          @vulnerability_backups = vulnerability_backups
          @restored_record_ids = {}
        end

        def execute
          ::SecApplicationRecord.transaction do
            disable_triggers
            restore
            delete_backups
          rescue StandardError => e
            log_and_raise_exception(e)
          end

          log_info
        end

        private

        attr_reader :vulnerability_backups, :restored_record_ids

        delegate :connection, to: SecApplicationRecord, private: true

        def disable_triggers
          connection.execute("SELECT set_config('vulnerability_management.dont_execute_db_trigger', 'true', true)")
        end

        def restore
          restore_findings

          return unless restored_finding_ids.present?

          restore_vulnerabilities
          restore_records_scoped_to_findings
          restore_records_scoped_to_vulnerabilities
          adjust_vulnerability_reads_attributes
          restore_with_on_the_fly_computations
          remove_archived_records
        end

        def delete_backups
          restored_record_ids.each do |model, restored_records|
            next unless restored_records.present?

            model.by_original_ids(restored_records).delete_all
          end
        end

        def restore_findings
          restore_records_from(Vulnerabilities::Backups::Finding, all_vulnerability_ids)
        end

        def restore_vulnerabilities
          Tasks::RestoreVulnerabilities.execute(vulnerability_backups_to_restore)
          Tasks::AttachFindingsToVulnerabilities.execute(vulnerability_backups_to_restore)
        end

        def restore_records_scoped_to_findings
          restore_records(BACKUPS_SCOPED_TO_FINDINGS, restored_finding_ids)
        end

        def restore_records_scoped_to_vulnerabilities
          restore_records(BACKUPS_SCOPED_TO_VULNERABILITIES, restored_vulnerability_ids)
        end

        def adjust_vulnerability_reads_attributes
          Tasks::AdjustTraversalIdsAndArchivedAttributes.execute(vulnerability_backups_to_restore)
        end

        def remove_archived_records
          Tasks::UpdateArchives.execute(restored_vulnerability_ids)
        end

        def restore_records(backup_models, restored_parent_ids)
          backup_models.each do |backup_model|
            restore_records_from(backup_model, restored_parent_ids)
          end
        end

        def restore_records_from(backup_model, restored_parent_ids)
          restored = Tasks::RestoreRecordsFromBackup.execute(backup_model, restored_parent_ids)

          restored_record_ids[backup_model] = restored
        end

        def restored_finding_ids
          @restored_finding_ids ||= restored_record_ids[Vulnerabilities::Backups::Finding]
        end

        def all_vulnerability_ids
          vulnerability_backups.map(&:original_record_identifier)
        end

        def restored_vulnerability_ids
          vulnerability_backups_to_restore.map(&:original_record_identifier)
        end

        def restore_with_on_the_fly_computations
          ::Vulnerabilities::Findings::RiskScoreCalculationService.new(restored_vulnerability_ids).execute
        end

        def vulnerability_backups_to_restore
          @vulnerability_backups_to_restore ||= vulnerability_backups.select do |backup|
            backup.data['finding_id'].in?(restored_finding_ids)
          end
        end

        def log_info
          ::Gitlab::AppLogger.info(
            message: 'Batch of vulnerabilities are restored',
            batch_size: vulnerability_backups.length,
            restored_vulnerability_count: vulnerability_backups_to_restore.length,
            class_name: self.class.name
          )
        end

        def log_and_raise_exception(error)
          Gitlab::ErrorTracking.log_and_raise_exception(error, { class_name: self.class.name })
        end
      end
    end
  end
end
