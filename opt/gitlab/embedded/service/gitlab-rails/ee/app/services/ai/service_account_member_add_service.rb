# frozen_string_literal: true

module Ai
  class ServiceAccountMemberAddService
    def initialize(project, service_account_user)
      @project = project
      @service_account_user = service_account_user
    end

    def execute
      existing_member = project.member(service_account_user)
      return ServiceResponse.success(message: "Membership already exists. Nothing to do.") if existing_member

      return ServiceResponse.error(message: "Service account user not found") unless service_account_user

      # We must sync project_authorizations immediately to the service_account_user here because the next
      # steps in StartWorkflowService are immediately going to trigger permission checks and Gitaly callbacks on
      # behalf of the service account which check they have permissions to create a branch in this project.
      result = project.add_member(service_account_user, :developer, immediately_sync_authorizations: true)

      if result && result.persisted?
        ServiceResponse.success(payload: result)
      else
        log_member_addition_failure(result)
        ServiceResponse.error(message: "Failed to add service account as developer")
      end
    end

    private

    attr_reader :project, :service_account_user

    def log_member_addition_failure(result)
      error_message = extract_error_details(result)

      log_data = {
        message: 'Failed to add service account as developer',
        project_id: project.id,
        service_account_user_id: service_account_user.id,
        error_details: error_message,
        group_membership_lock: project.group&.membership_lock,
        root_ancestor_membership_lock: project.root_ancestor&.membership_lock
      }

      Gitlab::AppLogger.error(log_data)
    rescue StandardError => e
      Gitlab::AppLogger.error(
        message: 'Failed to add service account as developer (logging error)',
        project_id: project&.id,
        service_account_user_id: service_account_user&.id,
        logging_error: "#{e.class.name}: #{e.message}"
      )
    end

    def extract_error_details(result)
      case result
      when false
        "add_member returned false (group_member_lock is enabled and user is not a bot)"
      when nil
        "add_member returned nil (empty result array or transaction failure)"
      when ActiveRecord::Base
        if result.errors.any?
          error_messages = result.errors.full_messages.join(', ')
          "Member validation/authorization errors: #{error_messages}"
        else
          "Member object returned but not persisted (possible save failure or approval failure)"
        end
      else
        "Unexpected return type from add_member: #{result.class.name}"
      end
    end
  end
end
