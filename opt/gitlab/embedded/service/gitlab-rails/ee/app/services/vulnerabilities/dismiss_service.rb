# frozen_string_literal: true

require_dependency 'vulnerabilities/base_service'

module Vulnerabilities
  class DismissService < BaseService
    include Security::ScanResultPolicies::SyncOnVulnerabilityStateChange

    FindingsDismissResult = Struct.new(:ok?, :finding, :message)

    def initialize(current_user, vulnerability, comment = nil, dismissal_reason = nil, dismiss_findings: true)
      super(current_user, vulnerability)
      @comment = comment
      @dismissal_reason = dismissal_reason
      @dismiss_findings = dismiss_findings
    end

    def execute
      raise Gitlab::Access::AccessDeniedError unless authorized?

      update_vulnerability_with(state: :dismissed, dismissed_by: @user, dismissed_at: Time.current,
        auto_resolved: false) do
        begin
          Vulnerabilities::StateTransition.create!(
            vulnerability: @vulnerability,
            vulnerability_occurrence_id: @vulnerability.finding_id,
            from_state: @vulnerability.state,
            to_state: :dismissed,
            comment: @comment,
            dismissal_reason: @dismissal_reason,
            author: @user
          )

        rescue ActiveRecord::RecordInvalid => invalid
          errors = invalid.record.errors
          messages = errors.full_messages.join
          raise Gitlab::Graphql::Errors::ArgumentError, messages if errors[:to_state].present?
        end

        if dismiss_findings
          result = dismiss_vulnerability_findings

          unless result.ok?
            handle_finding_dismissal_error(result.finding, result.message)
            raise ActiveRecord::Rollback
          end
        end
      end

      if Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function, @project)
        Vulnerabilities::Reads::UpsertService.new(@vulnerability,
          { state: :dismissed, dismissal_reason: @dismissal_reason }, projects: @project,
          findings: Array(@vulnerability.finding)).execute
      else
        # When the trigger is active, it handles state updates but not dismissal_reason
        @vulnerability.vulnerability_read&.update(dismissal_reason: @dismissal_reason)
      end

      sync_preexisting_state_approvals(@project) if @changed

      @vulnerability
    end

    private

    attr_reader :dismiss_findings

    def feedback_service_for(finding)
      VulnerabilityFeedback::CreateService.new(@project, @user, feedback_params_for(finding))
    end

    def feedback_params_for(finding)
      {
        category: finding.report_type,
        feedback_type: 'dismissal',
        comment: @comment,
        dismissal_reason: @dismissal_reason,
        pipeline: @project.vulnerability_statistic&.pipeline,
        finding_uuid: finding.uuid,
        dismiss_vulnerability: false,
        migrated_to_state_transition: true
      }
    end

    def dismiss_vulnerability_findings
      @vulnerability.findings.each do |finding|
        result = feedback_service_for(finding).execute

        return FindingsDismissResult.new(false, finding, result[:message]) if result[:status] == :error
      end

      FindingsDismissResult.new(true)
    end

    def handle_finding_dismissal_error(finding, message)
      @vulnerability.errors.add(
        :base,
        :finding_dismissal_error,
        message: _("failed to dismiss associated finding(id=%{finding_id}): %{message}") %
          {
            finding_id: finding.id,
            message: message
          })
    end

    def required_permission
      :dismiss_vulnerability
    end
  end
end
