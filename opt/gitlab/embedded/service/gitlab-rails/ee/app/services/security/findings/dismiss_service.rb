# frozen_string_literal: true

module Security
  module Findings
    class DismissService < BaseProjectService
      include Gitlab::Allowable
      include Security::ScanResultPolicies::SyncOnVulnerabilityStateChange

      def initialize(user:, security_finding:, comment: nil, dismissal_reason: nil)
        super(project: security_finding.project, current_user: user)
        @security_finding = security_finding
        @comment = comment
        @dismissal_reason = dismissal_reason
      end

      def execute
        return ServiceResponse.error(message: "Access denied", http_status: :forbidden) unless authorized?

        dismiss_finding
      end

      private

      def authorized?
        can?(@current_user, :admin_vulnerability, @project)
      end

      def dismiss_finding
        @error_message = nil
        @vulnerability = nil

        SecApplicationRecord.transaction do
          create_or_update_feedback
          create_and_dismiss_vulnerability
        end

        if @error_message
          error_string = format(_("failed to dismiss security finding: %{message}"), message: @error_message)
          ServiceResponse.error(message: error_string, http_status: :unprocessable_entity)
        else
          trigger_webhook_event
          schedule_sync_merge_request_approvals_worker
          sync_preexisting_state_approvals(@project)
          ServiceResponse.success(payload: { security_finding: @security_finding })
        end
      end

      # This method will be removed after the deprecation of Vulnerability Feedbacks is declared successful
      # It is a temporary measure to permit revert to Feedbacks if necessary.
      def create_or_update_feedback
        feedback = @project
          .vulnerability_feedback
          .with_feedback_type('dismissal')
          .by_finding_uuid([@security_finding.uuid]).first

        if feedback
          # We want to update existing feedback only for comment
          feedback.update!(vulnerability_feedback_attributes)
        else
          result = ::VulnerabilityFeedback::CreateService.new(
            @project,
            @current_user,
            feedback_params
          ).execute

          return if result[:status] == :success

          @error_message = result[:message].full_messages.join(",")
          raise ActiveRecord::Rollback
        end
      end

      def create_and_dismiss_vulnerability
        security_finding_params = {
          security_finding_uuid: @security_finding.uuid,
          comment: @comment,
          dismissal_reason: @dismissal_reason
        }

        result = ::Vulnerabilities::FindOrCreateFromSecurityFindingService.new(
          project: @project,
          current_user: @current_user,
          params: security_finding_params,
          state: :dismissed,
          present_on_default_branch: false
        ).execute

        if result.reason == :tracked_context_busy
          @error_message = result.message
          raise ActiveRecord::Rollback
        end

        return unless result.success?

        @vulnerability = result.payload[:vulnerability]
      end

      def trigger_webhook_event
        @vulnerability&.trigger_webhook_event
      end

      def feedback_params
        {
          category: @security_finding.scan_type,
          feedback_type: 'dismissal',
          comment: @comment,
          dismissal_reason: @dismissal_reason,
          pipeline: @security_finding.pipeline,
          finding_uuid: @security_finding.uuid,
          dismiss_vulnerability: false,
          migrated_to_state_transition: true
        }
      end

      def vulnerability_feedback_attributes
        if @comment.present?
          { comment: @comment, comment_timestamp: Time.zone.now, comment_author: @current_user }
        else
          { comment: nil, comment_timestamp: nil, comment_author: nil }
        end
      end

      def schedule_sync_merge_request_approvals_worker
        pipeline = @security_finding.pipeline

        # we are scheduling this in 1 minute so we can deduplicate if multiple findings are dismissed
        ::Security::ScanResultPolicies::SyncFindingsToApprovalRulesWorker.perform_in(
          SYNC_POLICIES_DELAY,
          pipeline.id
        )
      end
    end
  end
end
