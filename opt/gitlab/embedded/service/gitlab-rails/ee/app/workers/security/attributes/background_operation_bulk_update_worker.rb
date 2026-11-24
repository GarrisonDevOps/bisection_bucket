# frozen_string_literal: true

module Security
  module Attributes
    class BackgroundOperationBulkUpdateWorker
      include ApplicationWorker
      include Security::BackgroundOperationTracking

      data_consistency :sticky
      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:project_to_security_attributes], 30.seconds
      idempotent!

      def perform(project_ids, attribute_ids, mode, user_id, operation_id)
        @user = User.find_by_id(user_id)
        @operation_id = operation_id
        return unless @user
        return unless operation_exists?

        projects = Project.by_ids(project_ids).with_namespaces
        projects = projects.inc_routes.with_security_attributes if mode == 'REPLACE'

        projects.each do |project|
          process_project(project, attribute_ids, mode)
        end

        finalize_if_complete
      end

      private

      def process_project(project, attribute_ids, mode)
        service_params = build_service_params(project, attribute_ids, mode)

        result = ::Security::Attributes::UpdateProjectAttributesService.new(
          project: project,
          current_user: user,
          params: service_params
        ).execute

        if result.success?
          record_success
        else
          record_failure(project, result.message)
        end
      rescue StandardError => e
        record_failure(project, e.message)
        Gitlab::ErrorTracking.track_exception(e, operation_id: operation_id, project_id: project.id)
      end

      def build_service_params(project, attribute_ids, mode)
        {
          attributes: {
            add_attribute_ids: mode == 'REMOVE' ? [] : attribute_ids,
            remove_attribute_ids: remove_attribute_ids(project, attribute_ids, mode)
          }
        }
      end

      def remove_attribute_ids(project, attribute_ids, mode)
        return attribute_ids if mode == 'REMOVE'
        return [] if mode == 'ADD'

        # For the 'REPLACE' mode, we select all existing attribute ids (excluding soft-deleted ones)
        project.security_attributes.not_deleted.pluck_id
      end
    end
  end
end
