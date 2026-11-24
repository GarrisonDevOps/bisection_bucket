# frozen_string_literal: true

module WorkItems
  module Types
    class BaseService < BaseContainerService
      include Gitlab::InternalEventsTracking

      InvalidContainerForSaasError = ServiceResponse.error(
        message: 'Work item types can only be modified at the root group level'
      )

      InvalidContainerForSelfManagedError = ServiceResponse.error(
        message: 'Work item types can only be modified at the organization level'
      )

      def initialize(container:, current_user: nil, params: {})
        super
      end

      private

      def resolved_container
        container.respond_to?(:sync) ? container.sync : container
      end
      strong_memoize_attr :resolved_container

      def group_container?
        resolved_container.is_a?(::Group)
      end
      strong_memoize_attr :group_container?

      def saas_feature?
        ::Gitlab::Saas.feature_available?(:namespace_scoped_work_item_types)
      end
      strong_memoize_attr :saas_feature?

      def valid_container?
        return group_container? && resolved_container.root? if saas_feature?

        resolved_container.is_a?(::Organizations::Organization)
      end

      def invalid_container_error
        return InvalidContainerForSaasError if saas_feature?

        InvalidContainerForSelfManagedError
      end

      def validation_error_response(record)
        ServiceResponse.error(message: record.errors.full_messages.to_sentence)
      end

      def work_item_type_provider
        ::WorkItems::TypesFramework::Provider.new(resolved_container)
      end
      strong_memoize_attr :work_item_type_provider

      def tracking_namespace
        group_container? ? resolved_container : nil
      end

      def upsert_default_visibility(work_item_type)
        return if params[:enabled_by_default_for_new_namespaces].nil?

        settings = ::WorkItems::Settings.for_namespace(resolved_container)
        return unless settings

        ::WorkItems::TypesFramework::VisibilityDefault.upsert_for_settings(
          settings,
          work_item_type_id: work_item_type.persistable_id,
          enabled: params[:enabled_by_default_for_new_namespaces]
        )
      end
    end
  end
end
