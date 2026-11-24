# frozen_string_literal: true

module EE
  module Organizations
    module OrganizationHelper
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :organization_show_app_data
      def organization_show_app_data(organization)
        data = ::Gitlab::Json.safe_parse(super)
        path = artifact_registry_overview_path(organization)
        data[:artifact_registry_path] = path if path

        data.to_json
      end

      override :organization_activity_app_data
      def organization_activity_app_data(organization)
        ::Gitlab::Json.safe_parse(super).merge(
          organization_activity_event_types: organization_activity_event_types
        ).to_json
      end

      override :organization_settings_general_app_data
      def organization_settings_general_app_data(organization)
        ::Gitlab::Json.safe_parse(super).merge(
          policy_store_experiment_available: organization.policy_store_experiment_available?,
          policy_store_experiment_enabled: organization.policy_store_experiment_enabled?
        ).to_json
      end

      private

      def artifact_registry_overview_path(organization)
        return unless ::ArtifactRegistry::Configuration.configured?
        return unless can?(current_user, :read_artifact_registry, organization)
        return unless ::Feature.enabled?(:artifact_registry_ui, organization)

        slug = organization.artifact_registry_resolved_slug
        return artifact_registry_repositories_organization_path(organization, slug) if slug

        return if organization.artifact_registry_activated?
        return unless can?(current_user, :update_organization, organization)

        artifact_registry_organization_index_path(organization)
      end

      override :organization_activity_event_types
      def organization_activity_event_types
        super.concat([
          {
            title: _('Epic'),
            value: EventFilter::EPIC
          }
        ]).sort_by { |event| event[:value] }
      end
    end
  end
end
