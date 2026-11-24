# frozen_string_literal: true

module Analytics
  class ProjectAnalyticsChangesAuditor < ::AuditEvents::BaseChangesAuditor
    ATTRIBUTE_NAMES = [
      :product_analytics_configurator_connection_string,
      :product_analytics_data_collector_host,
      :cube_api_base_url,
      :cube_api_key
    ].freeze

    def initialize(current_user, project_setting, project)
      @project = project

      super(current_user, project_setting)
    end

    def execute
      ATTRIBUTE_NAMES.each do |attr|
        next unless model.previous_changes.key?(attr.to_s)

        audit_context = {
          name: 'product_analytics_settings_update',
          author: @current_user,
          scope: @project,
          target: @project,
          message: "Changed #{attr}",
          additional_details: details(attr)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      audit_pointer_changes
    end

    private

    def audit_pointer_changes
      return unless model.project&.analytics_dashboards_pointer&.previous_changes&.any?

      audit_context = {
        name: 'product_analytics_settings_update',
        author: @current_user,
        scope: @project,
        target: @project,
        message: "Changed analytics dashboards pointer",
        additional_details: {
          change: :analytics_dashboards_pointer,
          from: model.project.analytics_dashboards_pointer.previous_changes[:target_project_id].first,
          to: model.project.analytics_dashboards_pointer.previous_changes[:target_project_id].last
        }
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    def details(column)
      return { change: column } if
        [:product_analytics_configurator_connection_string, :cube_api_key].include?(column)

      {
        change: column,
        from: @model.previous_changes[column].first,
        to: @model.previous_changes[column].last
      }
    end
  end
end
