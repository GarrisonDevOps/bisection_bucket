# frozen_string_literal: true

module Projects
  class ProjectFeatureChangesAuditor < ::AuditEvents::BaseChangesAuditor
    attr_accessor :project

    COLUMNS_EVENT_TYPE_HASH = {
      merge_requests_access_level: 'project_feature_merge_requests_access_level_updated',
      forking_access_level: 'project_feature_forking_access_level_updated',
      issues_access_level: 'project_feature_issues_access_level_updated',
      wiki_access_level: 'project_feature_wiki_access_level_updated',
      snippets_access_level: 'project_feature_snippets_access_level_updated',
      builds_access_level: 'project_feature_builds_access_level_updated',
      repository_access_level: 'project_feature_repository_access_level_updated',
      package_registry_access_level: 'project_feature_package_registry_access_level_updated',
      pages_access_level: 'project_feature_pages_access_level_updated',
      metrics_dashboard_access_level: 'project_feature_metrics_dashboard_access_level_updated',
      analytics_access_level: 'project_feature_analytics_access_level_updated',
      operations_access_level: 'project_feature_operations_access_level_updated',
      requirements_access_level: 'project_feature_requirements_access_level_updated',
      security_and_compliance_access_level: 'project_feature_security_and_compliance_access_level_updated',
      container_registry_access_level: 'project_feature_container_registry_access_level_updated',
      monitor_access_level: 'project_feature_monitor_access_level_updated',
      infrastructure_access_level: 'project_feature_infrastructure_access_level_updated',
      feature_flags_access_level: 'project_feature_feature_flags_access_level_updated',
      environments_access_level: 'project_feature_environments_access_level_updated',
      releases_access_level: 'project_feature_releases_access_level_updated',
      model_experiments_access_level: 'project_feature_model_experiments_access_level_updated',
      model_registry_access_level: 'project_feature_model_registry_access_level_updated'
    }.freeze

    COLUMNS_HUMAN_NAME = {
      merge_requests_access_level: 'merge requests',
      forking_access_level: 'forks',
      issues_access_level: 'issues',
      wiki_access_level: 'wiki',
      snippets_access_level: 'snippets',
      builds_access_level: 'CI/CD',
      repository_access_level: 'repository',
      package_registry_access_level: 'package registry',
      pages_access_level: 'pages',
      metrics_dashboard_access_level: 'metrics dashboard',
      analytics_access_level: 'analytics',
      operations_access_level: 'operations access',
      requirements_access_level: 'requirements',
      security_and_compliance_access_level: 'security and compliance',
      container_registry_access_level: 'container registry',
      monitor_access_level: 'monitor',
      infrastructure_access_level: 'infrastructure',
      feature_flags_access_level: 'feature flags',
      environments_access_level: 'environments',
      releases_access_level: 'releases',
      model_experiments_access_level: 'model experiments',
      model_registry_access_level: 'model registry'
    }.with_indifferent_access.freeze

    def initialize(current_user, model, project)
      @project = project

      super(current_user, model)
    end

    def execute
      COLUMNS_EVENT_TYPE_HASH.each do |column, event_name|
        audit_changes(column, as: COLUMNS_HUMAN_NAME.fetch(column, column).to_s, entity: @project, model: model,
          event_type: event_name)
      end
    end

    def attributes_from_auditable_model(column)
      base_data = { target_details: @project.full_path }

      return base_data unless COLUMNS_EVENT_TYPE_HASH.key?(column)

      {
        from: ProjectFeature.str_from_access_level(model.previous_changes[column].first),
        to: ProjectFeature.str_from_access_level(model.previous_changes[column].last)
      }.merge(base_data)
    end
  end
end
