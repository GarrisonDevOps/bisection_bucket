# frozen_string_literal: true

module DependencyManagement
  class ProvisionServiceAccountService
    include Gitlab::ExclusiveLeaseHelpers

    SERVICE_ACCOUNT_NAME = 'GitLab Dependency Management'
    LEASE_TIMEOUT = 1.minute

    def initialize(project:)
      @project = project
    end

    def execute
      existing = project.dependency_management_service_account
      return ServiceResponse.success(payload: { user: existing }) if existing

      in_lock(lease_key, ttl: LEASE_TIMEOUT, retries: 10, sleep_sec: 0.5.seconds) do
        # Re-check after acquiring lock
        existing = project.reset.dependency_management_service_account
        break ServiceResponse.success(payload: { user: existing }) if existing

        create_and_provision_service_account
      end
    rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
      ServiceResponse.error(message: 'Could not obtain lock for service account provisioning')
    end

    private

    attr_reader :project

    def lease_key
      "dependency_management:provision_service_account:#{project.id}"
    end

    def create_and_provision_service_account
      result = create_service_account
      return result unless result.success?

      user = result.payload[:user]

      add_result = add_as_guest(user)
      unless add_result.success?
        cleanup_orphaned_user(user)
        return add_result
      end

      ServiceResponse.success(payload: { user: user })
    end

    def create_service_account
      admin_bot = Users::Internal.in_organization(project.organization).admin_bot

      unless admin_bot
        return ServiceResponse.error(
          message: 'Admin bot not found for the project organization'
        )
      end

      response = ::Namespaces::ServiceAccounts::ProjectCreateService.new(
        admin_bot,
        {
          name: SERVICE_ACCOUNT_NAME,
          project_id: project.id,
          organization_id: project.organization_id
        }
      ).execute

      if response[:status] == :success
        ServiceResponse.success(payload: { user: response[:user] })
      else
        Gitlab::AppLogger.error(
          message: 'Failed to create dependency management service account',
          reason: response[:message],
          project_id: project.id
        )
        ServiceResponse.error(message: "Failed to create service account")
      end
    end

    def add_as_guest(user)
      member = project.add_member(
        user,
        :guest,
        immediately_sync_authorizations: true
      )

      if member.nil?
        return ServiceResponse.error(
          message: 'Failed to add service account as guest: add_member returned nil'
        )
      end

      unless member.persisted?
        Gitlab::AppLogger.error(
          message: 'Failed to add service account as guest',
          project_id: project.id,
          error: member.errors.full_messages.to_sentence
        )

        return ServiceResponse.error(
          message: "Failed to add service account as guest"
        )
      end

      unless member.active?
        return ServiceResponse.error(
          message: 'Failed to add service account as guest: member is not active (possible user cap or membership lock)'
        )
      end

      ServiceResponse.success
    end

    def cleanup_orphaned_user(user)
      user.destroy

      return unless user.destroyed?

      reassigned_rules = user.reassigned_protected_environment_approval_rules
      log_protected_environment_reassignment_audit_events(user, reassigned_rules) if reassigned_rules.present?
    rescue StandardError => e
      Gitlab::AppLogger.error(
        message: 'Failed to clean up orphaned dependency management service account',
        user_id: user.id,
        project_id: project.id,
        error: e.message
      )
    end

    # One audit event per reassigned rule. Always attributed to the
    # system, since this service has no current_user - a service
    # account this new is not realistically a configured approver, but
    # the callback runs on every user destroy regardless.
    def log_protected_environment_reassignment_audit_events(user, rules)
      rules.each do |rule|
        protected_environment = rule.protected_environment

        audit_context = {
          name: 'protected_environment_approval_rule_reassigned',
          author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: protected_environment.project || protected_environment.group,
          target: protected_environment,
          target_details: protected_environment.name,
          message: "Sole approver #{user.username} was permanently deleted; " \
            "approval rule reassigned to require any Maintainer's approval",
          additional_details: {
            action: 'reassign_sole_approver',
            removed_user_id: user.id,
            protected_environment_id: protected_environment.id,
            new_access_level: rule.access_level
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
