# frozen_string_literal: true

module Integrations
  module SlackWorkspace
    class ChangeDuoGroupService < DuoGroupBaseService
      def execute
        failure = change_precondition_error
        return failure if failure

        release_stale_claim
        previous = ::Integrations::SlackWorkspace::Workspace.for_team(team_id)&.duo_namespace
        return previous ? disable(previous) : ServiceResponse.success unless group
        return enable_service.execute if previous.nil? || previous == group

        refusal = enable_service.refusal
        return refusal if refusal

        result = nil
        ::Integrations::SlackWorkspace::Workspace.transaction do
          result = disable(previous)
          result = enable_service.execute if result.success?
          raise ActiveRecord::Rollback unless result.success?
        end
        result
      end

      private

      def change_precondition_error
        return error(:not_available) unless ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(nil)
        return error(:missing_team) if team_id.blank?
        return error(:forbidden) unless current_user&.can_admin_all_resources?

        error(:not_top_level_group) if group && !(group.is_a?(::Group) && group.root?)
      end

      def release_stale_claim
        workspace = ::Integrations::SlackWorkspace::Workspace.for_team(team_id)
        ReleaseDuoGroupService.for(workspace).execute if workspace
      end

      def enable_service
        EnableDuoGroupService.new(group, current_user: current_user, team_id: team_id, admin_area: true)
      end
      strong_memoize_attr :enable_service

      def disable(previous)
        DisableDuoGroupService.new(previous, current_user: current_user, team_id: team_id, admin_area: true).execute
      end
    end
  end
end
