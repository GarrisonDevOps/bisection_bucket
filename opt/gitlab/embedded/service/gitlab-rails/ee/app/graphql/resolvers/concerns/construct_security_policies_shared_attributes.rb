# frozen_string_literal: true

module ConstructSecurityPoliciesSharedAttributes
  POLICY_YAML_ATTRIBUTES = %i[name description enabled policy_scope].freeze

  def edit_path(policy, type)
    id = CGI.escape(policy[:name])
    if policy[:namespace]
      Rails.application.routes.url_helpers.edit_group_security_policy_url(
        policy[:namespace], id: id, type: type
      )
    else
      Rails.application.routes.url_helpers.edit_project_security_policy_url(
        policy[:project], id: id, type: type
      )
    end
  end

  def policy_scope(scope_yaml)
    Security::SecurityOrchestrationPolicies::PolicyScopeFetcher
      .new(policy_scope: scope_yaml, container: container, current_user: current_user)
      .execute
  end

  def container
    object
  end

  def policy_blob_file_path(policy, warnings)
    project = pipeline_execution_policy_content_project(policy)
    if project
      content_include = policy.dig(:content, :include, 0)
      file = content_include[:file]
      ref = content_include[:ref] || project.default_branch_or_main
      Gitlab::Routing.url_helpers.project_blob_path(project, File.join(ref, file))
    else
      warnings << _('The policy is associated with a non-existing pipeline configuration file.')
      ""
    end
  end

  def pipeline_execution_policy_content_project(policy)
    content_include = policy.dig(:content, :include, 0)
    return unless content_include && content_include[:project]

    container.organization.projects.find_by_full_path(content_include[:project])
  end

  def policy_specific_attributes(type, policy_attributes, with_policy_attributes)
    if with_policy_attributes # for when querying generic policies
      { type: type, policy_attributes: policy_attributes.merge(type: type) }
    else # for when querying a specific policy type
      policy_attributes
    end
  end

  def base_policy_attributes(policy)
    {
      source: {
        project: policy[:project],
        namespace: policy[:namespace],
        inherited: policy[:inherited]
      }
    }
  end
end
