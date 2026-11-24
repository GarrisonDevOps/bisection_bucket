# frozen_string_literal: true

module Vulnerabilities
  class BulkDismissService < BaseBulkUpdateService
    include Security::ScanResultPolicies::SyncOnVulnerabilityStateChange

    def initialize(current_user, vulnerability_ids, comment, dismissal_reason)
      super(current_user, vulnerability_ids, comment)
      @dismissal_reason = dismissal_reason
    end

    private

    attr_reader :dismissal_reason

    def update(vulnerabilities_ids)
      selected_vulnerabilities = vulnerabilities_to_update(vulnerabilities_ids)
      vulnerability_attrs = vulnerabilities_attributes(selected_vulnerabilities)
      return if vulnerability_attrs.empty?

      db_attributes = db_attributes_for(vulnerability_attrs)
      projects = selected_vulnerabilities.with_projects.map(&:project).uniq

      SecApplicationRecord.feature_flagged_transaction_for(projects) do
        update_support_tables(selected_vulnerabilities, db_attributes, projects)
        selected_vulnerabilities.update_all(db_attributes[:vulnerabilities])
        SecApplicationRecord.current_transaction.after_commit do
          Vulnerabilities::BulkEsOperationService.new(selected_vulnerabilities).execute
        end

        projects.each { |project| sync_preexisting_state_approvals(project) }
      end

      attrs = vulnerability_attrs.map do |id, _, project_id, namespace_id|
        {
          vulnerability_id: id,
          project_id: project_id,
          namespace_id: namespace_id,
          dismissal_reason: dismissal_reason.to_s,
          comment: comment,
          user_id: user.id
        }
      end

      Gitlab::EventStore.publish(::Vulnerabilities::BulkDismissedEvent.new(data: { vulnerabilities: attrs }))
    end

    def vulnerabilities_to_update(ids)
      Vulnerability.id_in(ids)
    end

    def update_support_tables(vulnerabilities, db_attributes, projects)
      Vulnerabilities::StateTransition.insert_all!(db_attributes[:state_transitions])

      if projects.all? { |p| Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function, p) }
        Vulnerabilities::Reads::UpsertService.new(vulnerabilities, { dismissal_reason: dismissal_reason },
          projects: projects).execute
      else
        # When the trigger is active, it handles state updates but not dismissal_reason
        # The `insert_or_update_vulnerability_reads` database trigger does not
        # update the dismissal_reason and we are moving away from using
        # database triggers to keep tables up to date.
        # rubocop:disable Search/VulnerabilityBulkOperationElasticsearchSync -- ES sync handled by
        # BulkEsOperationService in the after_commit block within the update method
        Vulnerabilities::Read
          .by_vulnerabilities(vulnerabilities)
          .update_all(dismissal_reason: dismissal_reason, auto_resolved: false)
        # rubocop:enable Search/VulnerabilityBulkOperationElasticsearchSync
      end
    end

    def vulnerabilities_attributes(vulnerabilities)
      vulnerabilities
        .select(:id, :state, :project_id, :finding_id).with_projects
        .map { |v| [v.id, v.state, v.project_id, v.project.project_namespace_id, v.finding_id] }
    end

    def db_attributes_for(vulnerability_attrs)
      {
        vulnerabilities: vulnerabilities_update_attributes,
        state_transitions: transition_attributes_for(vulnerability_attrs)
      }
    end

    def vulnerabilities_update_attributes
      {
        state: :dismissed,
        auto_resolved: false,
        dismissed_by_id: user.id,
        dismissed_at: now,
        updated_at: now,
        confirmed_at: nil,
        confirmed_by_id: nil,
        resolved_at: nil,
        resolved_by_id: nil
      }
    end

    def transition_attributes_for(vulnerability_attrs)
      vulnerability_attrs.map do |id, state, _, _, finding_id|
        {
          vulnerability_id: id,
          vulnerability_occurrence_id: finding_id,
          from_state: state,
          to_state: :dismissed,
          comment: comment,
          dismissal_reason: dismissal_reason,
          author_id: user.id,
          created_at: now,
          updated_at: now
        }
      end
    end

    def required_permission
      :dismiss_vulnerability
    end
  end
end
