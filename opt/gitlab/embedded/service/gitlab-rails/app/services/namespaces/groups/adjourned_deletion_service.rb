# frozen_string_literal: true

# This service manages the group deletion process:
# - Permanently deletes the group if user has sufficient permissions.
# - Restores the group if user lacks necessary permissions.
# Note: This service should only be called from a Sidekiq context otherwise,
# `Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode` will raise an error.
module Namespaces
  module Groups
    class AdjournedDeletionService < ::BaseGroupService
      def execute
        if removable_group? && current_user_can_remove_group?
          delete_group
        else
          restore_group
        end
      end

      private

      def removable_group?
        !group.linked_to_subscription?
      end

      def current_user_can_remove_group?
        return false unless current_user

        Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode(current_user) do
          Ability.allowed?(current_user, :remove_group, group)
        end
      end

      def delete_group
        GroupDestroyWorker.perform_in(params[:delay], group.id, current_user.id)

        ServiceResponse.success(payload: { destroy_scheduled: true })
      end

      def restore_group
        admin_bot = ::Users::Internal.in_organization(group.organization_id).admin_bot
        result = Gitlab::Auth::CurrentUserMode.optionally_run_in_admin_mode(admin_bot) do
          ::Groups::RestoreService.new(group, admin_bot).execute
        end

        log_restore_failure(result) if result.error?

        result
      end

      # Otherwise the row stays overdue and the cron retries it every day without a trace.
      def log_restore_failure(result)
        Gitlab::AppLogger.warn(
          Labkit::Fields::LOG_MESSAGE => 'Adjourned group deletion could not restore group',
          Labkit::Fields::GL_NAMESPACE_ID => group.id,
          namespace_state: group.state_name.to_s,
          Labkit::Fields::ERROR_MESSAGE => result.message
        )
      end
    end
  end
end
