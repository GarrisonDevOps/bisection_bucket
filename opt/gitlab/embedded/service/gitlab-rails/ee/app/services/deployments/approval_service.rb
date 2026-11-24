# frozen_string_literal: true

module Deployments
  class ApprovalService < ::BaseService
    include Gitlab::Utils::StrongMemoize

    attr_reader :deployment

    delegate :environment, to: :deployment

    def execute(deployment, status)
      @deployment = deployment

      error_message = validate(deployment, status)
      return error(error_message) if error_message

      approval = upsert_approval(deployment, status, params[:comment])
      return error(approval.errors.full_messages) if approval.errors.any?

      # A repeated identical decision is a no-op: `upsert_approval` returns the
      # existing approval unchanged, so skip audit logging, webhooks, and build
      # processing to avoid firing duplicate side effects.
      return success(approval: approval) unless approval.saved_changes?

      create_audit_event(deployment, approval)
      deployment.execute_approval_hooks(approval, current_user)

      process_build!(deployment, approval)

      deployment.invalidate_cache

      success(approval: approval)
    end

    private

    def upsert_approval(deployment, status, comment)
      if approval = deployment.approvals.find_by_user_id_and_approval_rule_id(
        current_user.id, approval_rule&.id
      )

        return approval if approval.status == status

        approval.tap { |a| a.update(status: status, comment: comment) }
      elsif environment.has_approval_rules?
        deployment.approvals.create(user: current_user, status: status, comment: comment, approval_rule: approval_rule)
      else
        deployment.approvals.create(user: current_user, status: status, comment: comment)
      end
    end

    def create_audit_event(deployment, approval)
      audit_context = {
        name: "deployment_#{approval.status}",
        author: current_user,
        scope: deployment.project,
        target: deployment.environment,
        message: "#{approval.status.capitalize} deployment with IID: #{deployment.iid} and ID: #{deployment.id}",
        additional_details: {
          comment: approval.comment
        }
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    def process_build!(deployment, approval)
      return unless deployment.deployable

      if approval.rejected?
        deployment.deployable.drop!(:deployment_rejected)
      elsif environment.has_approval_rules?
        # No-op
        # Approvers might not have sufficient permission to execute the deployment job,
        # so we just unblock the deployment, which stays as manual job.
        # Executors can later run the manual job at their ideal timing.
      elsif deployment.pending_approval_count <= 0
        deployment.deployable.enqueue!
      end
    end

    # rubocop:disable Style/GuardClause
    def validate(deployment, status)
      return _('Unrecognized approval status.') unless Deployments::Approval.statuses.include?(status)
      return _('This environment is not protected.') unless deployment.environment.protected?

      if deployment.user == current_user && status == 'approved' &&
          !deployment.allow_pipeline_trigger_approve_deployment
        return _('You cannot approve your own deployment. This configuration can be adjusted in the protected environment settings.')
      end

      unless deployment.environment.needs_approval?
        return _('Deployment approvals is not configured for this environment.')
      end

      return _('This deployment is not waiting for approvals.') unless deployment.waiting_for_approval?

      unless Ability.allowed?(current_user, :approve_deployment, deployment)
        return _("You don't have permission to approve this deployment. Contact the project or group owner for help.")
      end

      if environment.has_approval_rules? && params[:represented_as].present? && approval_rule.nil?
        _("There are no approval rules for the given `represent_as` parameter. " \
          "Use a valid User/Group/Role name instead.")
      end
    end
    # rubocop:enable Style/GuardClause

    def approval_rule
      strong_memoize(:approval_rule) do
        environment.find_approval_rule_for(current_user, represented_as: params[:represented_as])
      end
    end
  end
end
