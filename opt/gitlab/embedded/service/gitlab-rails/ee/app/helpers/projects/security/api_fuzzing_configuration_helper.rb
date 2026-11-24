# frozen_string_literal: true

module Projects::Security::ApiFuzzingConfigurationHelper
  def api_fuzzing_configuration_data(project)
    {
      security_configuration_path: project_security_configuration_path(project),
      full_path: project.full_path,
      gitlab_ci_yaml_edit_path: Rails.application.routes.url_helpers.project_ci_pipeline_editor_path(project),
      api_fuzzing_documentation_path: help_page_path('user/application_security/api_fuzzing/_index.md'),
      api_fuzzing_authentication_documentation_path: help_page_path('user/application_security/api_fuzzing/configuration/customizing_analyzer_settings.md', anchor: 'authentication'),
      ci_variables_documentation_path: help_page_path('ci/variables/_index.md'),
      project_ci_settings_path: project_settings_ci_cd_path(project),
      can_set_project_ci_variables: can?(current_user, :admin_pipeline, project).to_s
    }
  end
end
