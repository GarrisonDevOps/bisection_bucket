# frozen_string_literal: true

module WorkItems
  module Types
    class UpdateService < BaseService
      WorkItemTypeNotFoundError = ServiceResponse.error(
        message: 'Work item type not found'
      )
      ArchivedItemNameIconUpdateError = ServiceResponse.error(
        message: 'Cannot update name or icon of an archived work item type'
      )
      NonConfigurableTypeError = ServiceResponse.error(
        message: 'Work item type is not configurable'
      )
      SystemTypeArchiveAndNameIconUpdateError = ServiceResponse.error(
        message: 'Cannot update name or icon of a system defined work item type and archive it simultaneously'
      )

      def execute
        return invalid_container_error unless valid_container?
        return WorkItemTypeNotFoundError unless work_item_type
        return NonConfigurableTypeError unless work_item_type.configurable?
        return ArchivedItemNameIconUpdateError if archived_item_name_icon_update_attempted?
        return SystemTypeArchiveAndNameIconUpdateError if system_type_archive_and_name_icon_update_attempted?

        update_work_item_type
      end

      private

      def work_item_type
        return unless params[:id]

        work_item_type_provider.find_by_id(GlobalID.parse(params[:id])&.model_id)
      end
      strong_memoize_attr :work_item_type

      def update_work_item_type
        custom_work_item_type? ? update_custom_work_item_type : create_custom_work_item_type
      end

      def update_custom_work_item_type
        if work_item_type.update(build_params)
          upsert_default_visibility(work_item_type)
          track_update_events

          ServiceResponse.success(payload: {
            work_item_type: work_item_type,
            resource_parent: resolved_container
          })
        else
          validation_error_response(work_item_type)
        end
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      def create_custom_work_item_type
        create_params = build_params.merge(
          converted_from_system_defined_type_identifier: work_item_type.id
        )

        unless params[:enabled_by_default_for_new_namespaces].nil?
          create_params[:enabled_by_default_for_new_namespaces] =
            params[:enabled_by_default_for_new_namespaces]
        end

        result = ::WorkItems::Types::CreateService.new(
          container: resolved_container,
          current_user: current_user,
          params: create_params
        ).execute

        track_update_events if result.success?

        result
      end

      def build_params
        custom_work_item_type? ? build_update_params : build_conversion_params
      end

      def system_work_item_type?
        work_item_type.is_a?(WorkItems::TypesFramework::SystemDefined::Type)
      end

      def custom_work_item_type?
        work_item_type.is_a?(WorkItems::TypesFramework::Custom::Type)
      end

      def build_update_params
        {}.tap do |params_hash|
          params_hash[:name] = params[:name] if params[:name].present?
          params_hash[:icon_name] = params[:icon_name] if params[:icon_name].present?
          params_hash[:archived] = params[:archive] if params.key?(:archive)
        end
      end

      def build_conversion_params
        {}.tap do |params_hash|
          params_hash[:name] = params[:name].presence || work_item_type.name
          params_hash[:icon_name] = params[:icon_name].presence || work_item_type.icon_name
          params_hash[:archived] = params[:archive] if params.key?(:archive)
        end
      end

      def system_type_archive_and_name_icon_update_attempted?
        system_work_item_type? && params[:archive] == true && (params[:name].present? || params[:icon_name].present?)
      end

      def archived_item_name_icon_update_attempted?
        work_item_type.archived? && (params[:name].present? || params[:icon_name].present?)
      end

      def track_update_events
        if params.key?(:archive)
          track_internal_event('archive_work_item_type',
            namespace: tracking_namespace,
            user: current_user,
            additional_properties: {
              label: work_item_type.name,
              property: params[:archive].to_s
            }
          )
        end

        return unless params[:name].present? || params[:icon_name].present?

        track_internal_event('update_work_item_type',
          namespace: tracking_namespace,
          user: current_user,
          additional_properties: {
            label: work_item_type.name
          }
        )
      end
    end
  end
end
