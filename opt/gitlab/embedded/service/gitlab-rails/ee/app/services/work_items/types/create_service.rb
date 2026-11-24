# frozen_string_literal: true

module WorkItems
  module Types
    class CreateService < BaseService
      LIFECYCLE_BATCH_SIZE = 100

      def execute
        return invalid_container_error unless valid_container?

        custom_type = build_custom_type

        return validation_error_response(custom_type) unless custom_type.valid?

        ApplicationRecord.transaction do
          custom_type.save!
          work_item_type_provider.invalidate_cache!
          attach_to_custom_lifecycles(custom_type)
          upsert_default_visibility(custom_type)
        end

        upsert_default_visibility(custom_type)
        track_create_event(custom_type) unless conversion?

        ServiceResponse.success(payload: {
          work_item_type: custom_type,
          resource_parent: resolved_container
        })
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      def build_custom_type
        attributes = {
          name: params[:name],
          icon_name: params[:icon_name],
          converted_from_system_defined_type_identifier: params[:converted_from_system_defined_type_identifier]
        }

        # When archiving a system-defined type, UpdateService calls CreateService to creates a new custom type
        # and passes the archived param.
        attributes[:archived] = params[:archived] if params.key?(:archived)

        if resolved_container.is_a?(::Organizations::Organization)
          attributes[:organization_id] = resolved_container.id
        else
          attributes[:namespace_id] = resolved_container.id
        end

        ::WorkItems::TypesFramework::Custom::Type.new(attributes)
      end

      def attach_to_custom_lifecycles(custom_type)
        return if custom_type.converted_from_system_defined_type_identifier.present?

        if resolved_container.is_a?(::Organizations::Organization)
          attach_to_custom_lifecycle_for_organization(custom_type)
        else
          attach_to_custom_lifecycle_for_namespace(custom_type)
        end
      end

      def attach_to_custom_lifecycle_for_organization(custom_type)
        # Iterate over all groups in orgazation
        Group.in_organization(resolved_container).each_batch(of: LIFECYCLE_BATCH_SIZE) do |batch|
          # Fetch all the root groups that have a custom lifecycle attached for the given group batch.
          # rubocop:disable CodeReuse/ActiveRecord -- query only used here for root group lookup
          groups = batch.where(parent_id: nil)
            .joins(:type_custom_lifecycles)
            .includes(:type_custom_lifecycles).to_a
          # rubocop:enable CodeReuse/ActiveRecord

          next if groups.empty?

          records = build_records_for_batch(groups, custom_type)
          ::WorkItems::TypeCustomLifecycle.insert_all!(records) if records.present?
        end
      end

      def attach_to_custom_lifecycle_for_namespace(custom_type)
        type_custom_lifecycle = find_type_custom_lifecycle_target(resolved_container.type_custom_lifecycles)
        return unless type_custom_lifecycle

        ::WorkItems::TypeCustomLifecycle.create!(
          work_item_type_id: custom_type.id,
          lifecycle_id: type_custom_lifecycle.lifecycle_id,
          namespace_id: resolved_container.id
        )
      end

      def build_records_for_batch(namespaces, custom_type)
        namespaces.filter_map do |namespace|
          type_custom_lifecycle = find_type_custom_lifecycle_target(namespace.type_custom_lifecycles)

          {
            work_item_type_id: custom_type.id,
            lifecycle_id: type_custom_lifecycle.lifecycle_id,
            namespace_id: namespace.id
          }
        end
      end

      def find_type_custom_lifecycle_target(type_custom_lifecycles)
        issue_type_id = ::WorkItems::TypesFramework::Provider.new.default_issue_type.id
        type_custom_lifecycles.find { |r| r.work_item_type_id == issue_type_id } ||
          type_custom_lifecycles.first
      end

      def conversion?
        params[:converted_from_system_defined_type_identifier].present?
      end

      def track_create_event(custom_type)
        track_internal_event('create_work_item_type',
          namespace: tracking_namespace,
          user: current_user,
          additional_properties: {
            label: custom_type.name
          }
        )
      end
    end
  end
end
