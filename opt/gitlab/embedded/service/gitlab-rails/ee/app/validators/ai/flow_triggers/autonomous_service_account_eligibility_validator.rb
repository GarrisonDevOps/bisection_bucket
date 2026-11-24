# frozen_string_literal: true

module Ai
  module FlowTriggers
    class AutonomousServiceAccountEligibilityValidator
      include ActiveModel::Validations

      attr_reader :service_account, :project

      validate :must_be_service_account
      validate :must_be_scoped
      validate :must_be_active
      validate :must_be_project_member
      validate :must_not_hold_owner

      def initialize(service_account, project)
        @service_account = service_account
        @project = project
      end

      private

      def must_be_service_account
        return if service_account&.service_account?

        errors.add(:base, _('User must be a service account'))
      end

      def must_be_scoped
        return unless service_account&.service_account?
        return if service_account.provisioned_by_group_id.present? || service_account.provisioned_by_project_id.present?

        errors.add(:base, _('Service account must be group or project scoped, not instance-wide'))
      end

      def must_be_active
        return unless service_account
        return if service_account.active?

        errors.add(:base, _('Service account must be active'))
      end

      def must_be_project_member
        return unless service_account && project
        return if project.member?(service_account)

        errors.add(:base, _('Service account must be a member of the target project'))
      end

      # Provisioning never grants Owner, but nothing prevents someone raising the role
      # afterwards, so it is re-checked here: an unattended run must not hold the role that
      # can change roles.
      def must_not_hold_owner
        return unless service_account && project
        return unless project.team.max_member_access(service_account.id) == ::Gitlab::Access::OWNER

        errors.add(:base, _('Service account must not have the Owner role'))
      end
    end
  end
end
