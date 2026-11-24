# frozen_string_literal: true

module Vulnerabilities
  class BulkSeverityOverrideService < BaseBulkUpdateService
    include Gitlab::Utils::StrongMemoize
    include Security::ScanResultPolicies::SyncOnVulnerabilityStateChange

    def initialize(current_user, vulnerability_ids, comment, severity)
      super(current_user, vulnerability_ids, comment)
      @new_severity = severity
    end

    private

    def update(vulnerability_ids)
      vulnerabilities_attributes = vulnerabilities_attributes(vulnerabilities(vulnerability_ids))
      return if vulnerabilities_attributes.blank?

      changed = vulnerabilities_that_changed_severity(vulnerability_ids)
      update_vulnerabilities!(changed) if changed.any?

      create_notes!(vulnerabilities_attributes)
      audit_severity_changes(vulnerabilities_attributes)
      track_severity_changes(vulnerabilities_attributes)
    rescue StandardError => e
      track_severity_changes(vulnerabilities_attributes, e) if vulnerabilities_attributes.presence
      raise
    end

    def update_vulnerabilities!(vulnerabilities)
      attributes = vulnerabilities_attributes(vulnerabilities)
      db_attributes = db_attributes_for(attributes)

      vulnerability_ids_to_be_updated = vulnerabilities.map(&:id)
      projects = vulnerabilities.with_projects.map(&:project).uniq

      SecApplicationRecord.feature_flagged_transaction_for(projects) do
        vulnerability_ids = vulnerabilities.map(&:id)

        vulnerabilities.update_all(db_attributes[:vulnerabilities])
        update_support_tables(Vulnerability.by_ids(vulnerability_ids_to_be_updated), db_attributes, projects)

        SecApplicationRecord.current_transaction.after_commit do
          vulnerabilities_to_sync = Vulnerability.id_in(vulnerability_ids)

          ::Vulnerabilities::BulkEsOperationService.new(vulnerabilities_to_sync).execute
          ::Vulnerabilities::Findings::RiskScoreCalculationService.new(vulnerability_ids).execute
        end

        projects.each { |project| sync_preexisting_state_approvals(project) }
      end
    end

    def create_notes!(vulnerability_attributes)
      vulnerability_ids = extract_vulnerability_ids(vulnerability_attributes)
      latest_notes_by_vulnerability_ids = fetch_latest_system_notes(vulnerability_ids)

      attributes_to_insert = select_attributes_needing_new_note(
        vulnerability_attributes,
        latest_notes_by_vulnerability_ids
      )

      return if attributes_to_insert.empty?

      db_attributes = db_attributes_for(attributes_to_insert)

      Note.transaction do
        note_ids = Note.insert_all!(db_attributes[:system_notes], returning: %w[id])
        SystemNoteMetadata.insert_all!(system_note_metadata_attributes_for(note_ids))
      end
    end

    def extract_vulnerability_ids(vulnerability_attributes)
      vulnerability_attributes.map(&:first)
    end

    def fetch_latest_system_notes(vulnerability_ids)
      Note
        .system
        .with_noteable_type(Vulnerability.name)
        .with_noteable_ids(vulnerability_ids)
        .distinct_on_noteable_id
        .order_by_noteable_latest_first
        .index_by(&:noteable_id)
    end

    def select_attributes_needing_new_note(vulnerability_attributes, latest_notes_by_vulnerability_ids)
      vulnerability_attributes.select do |id, severity, *_|
        intended_note = formatted_severity_change_note(severity)

        last_note = latest_notes_by_vulnerability_ids[id]
        last_note.nil? || last_note.note != intended_note
      end
    end

    def formatted_severity_change_note(original_severity)
      if original_severity.to_s == @new_severity.to_s
        format(
          'changed comment to: "%{comment}"',
          comment: comment
        )
      else
        ::SystemNotes::VulnerabilitiesService.formatted_note(
          transition: 'changed',
          to_value: @new_severity,
          reason: nil,
          comment: comment,
          attribute: 'severity',
          from_value: original_severity
        )
      end
    end

    def authorized_for_project(project)
      super && Feature.disabled?(:hide_vulnerability_severity_override, project.root_ancestor)
    end

    def severity_overrides_attributes_for(vulnerability_attrs)
      vulnerability_attrs.map do |id, severity, project_id|
        {
          vulnerability_id: id,
          original_severity: severity,
          new_severity: @new_severity,
          project_id: project_id,
          author_id: user.id,
          created_at: now,
          updated_at: now
        }
      end
    end

    def audit_severity_changes(vulnerability_attrs)
      vulnerabilities_audit_attrs = vulnerability_attrs.filter_map do |_, severity, _, _, project, vulnerability|
        next if severity.to_s == @new_severity.to_s

        {
          old_severity: severity,
          project: project,
          vulnerability: vulnerability
        }
      end

      SeverityOverrideAuditService.new(
        vulnerabilities_audit_attrs: vulnerabilities_audit_attrs,
        now: now,
        current_user: user,
        new_severity: @new_severity
      ).execute
    end

    def db_attributes_for(vulnerability_attrs)
      {
        vulnerabilities: vulnerabilities_update_attributes,
        severity_overrides: severity_overrides_attributes_for(vulnerability_attrs),
        system_notes: system_note_attributes_for(vulnerability_attrs)
      }
    end

    def vulnerabilities(ids)
      strong_memoize_with(:vulnerabilities, ids.sort) do
        Vulnerability
          .id_in(ids)
          .with_projects_and_routes
      end
    end

    def vulnerabilities_that_changed_severity(ids)
      strong_memoize_with(:vulnerabilities_that_changed_severity, ids.sort) do
        vulnerabilities(ids).without_severities(@new_severity)
      end
    end

    def vulnerabilities_attributes(vulnerabilities)
      vulnerabilities.map do |v|
        [
          v.id,
          v.severity,
          v.project_id,
          v.project.project_namespace_id,
          v.project,
          v
        ]
      end
    end

    def vulnerabilities_update_attributes
      {
        severity: @new_severity,
        updated_at: now
      }
    end

    def update_support_tables(vulnerabilities, db_attributes, projects)
      Vulnerabilities::Finding.by_vulnerability(vulnerabilities).update_all(severity: @new_severity, updated_at: now)
      Vulnerabilities::SeverityOverride.insert_all!(db_attributes[:severity_overrides])
      Vulnerabilities::Reads::UpsertService.new(vulnerabilities, { severity: @new_severity },
        projects: projects).execute
    end

    def system_note_metadata_action
      "vulnerability_severity_changed"
    end

    def system_note_attributes_for(vulnerability_attrs)
      vulnerability_attrs.map do |id, severity, project_id|
        {
          noteable_type: "Vulnerability",
          noteable_id: id,
          project_id: project_id,
          system: true,
          note: formatted_severity_change_note(severity),
          author_id: user.id,
          created_at: now,
          updated_at: now,
          discussion_id: Discussion.discussion_id(Note.new({
            noteable_id: id,
            noteable_type: "Vulnerability"
          }))
        }
      end
    end

    def system_note_metadata_attributes_for(results)
      results.map do |row|
        id = row['id']
        {
          note_id: id,
          action: system_note_metadata_action,
          created_at: now,
          updated_at: now
        }
      end
    end

    def track_severity_changes(vulnerabilities_attributes, error = nil)
      vulnerabilities = vulnerabilities_attributes.map { |(_, _, _, _, _, vulnerability)| vulnerability }

      Vulnerabilities::ChangesTrackingService.new(
        user: user,
        category: self.class.name,
        vulnerabilities: vulnerabilities,
        new_value: @new_severity,
        field: :severity,
        error: error
      ).execute
    end

    def required_permission
      :update_vulnerability_severity
    end
  end
end
