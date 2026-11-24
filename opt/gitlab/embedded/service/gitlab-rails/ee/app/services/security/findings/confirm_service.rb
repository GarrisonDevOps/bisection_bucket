# frozen_string_literal: true

module Security
  module Findings
    class ConfirmService < BaseProjectService
      include Gitlab::Allowable
      include Security::ScanResultPolicies::SyncOnVulnerabilityStateChange

      def initialize(user:, security_finding:, comment: nil)
        super(project: security_finding.project, current_user: user)
        @security_finding = security_finding
        @comment = comment
      end

      def execute
        return ServiceResponse.error(message: "Access denied", reason: :forbidden) unless authorized?

        confirm_finding
      end

      private

      def authorized?
        can?(current_user, :confirm_vulnerability, project)
      end

      def confirm_finding
        result = ::Vulnerabilities::FindOrCreateFromSecurityFindingService.new(
          project: project,
          current_user: current_user,
          params: { security_finding_uuid: @security_finding.uuid, comment: @comment },
          state: :confirmed,
          present_on_default_branch: false,
          defer_existing_state_update: true
        ).execute

        unless result.success?
          error = format(_("failed to confirm security finding: %{message}"), message: result.message)
          return ServiceResponse.error(message: error, reason: :unprocessable_entity)
        end

        created = result.payload[:created]
        vulnerability = result.payload[:vulnerability]
        unless created || vulnerability.errors.any?
          vulnerability = ::Vulnerabilities::ConfirmService.new(current_user, vulnerability, @comment).execute
        end

        # CreateService reports failures (e.g. a concurrent attach) on the unsaved record, not the response.
        if vulnerability.errors.any?
          error = format(_("failed to confirm security finding: %{message}"),
            message: vulnerability.errors.full_messages.to_sentence)
          return ServiceResponse.error(message: error, reason: :unprocessable_entity)
        end

        if created
          vulnerability.trigger_webhook_event
          sync_preexisting_state_approvals(project)
        end

        schedule_sync_merge_request_approvals_worker

        ServiceResponse.success(payload: { security_finding: @security_finding })
      end

      def schedule_sync_merge_request_approvals_worker
        ::Security::ScanResultPolicies::SyncFindingsToApprovalRulesWorker.perform_in(
          SYNC_POLICIES_DELAY,
          @security_finding.pipeline.id
        )
      end
    end
  end
end
