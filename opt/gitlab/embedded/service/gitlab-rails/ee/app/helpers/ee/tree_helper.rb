# frozen_string_literal: true

module EE
  module TreeHelper
    extend ::Gitlab::Utils::Override

    override :vue_tree_header_app_data
    def vue_tree_header_app_data(project, repository, ref, ref_type)
      super.merge({
        kerberos_url: alternative_kerberos_url? ? project.kerberos_url_to_repo : ''
      }.merge(vue_tree_workspace_data))
    end

    override :vue_file_list_data
    def vue_file_list_data(project, ref)
      super.merge({
        resource_id: project.to_global_id,
        explain_code_available: tree_explain_code_available?(project).to_s
      })
    end

    override :vue_repository_app_data
    def vue_repository_app_data(project, repository, ref, ref_type, blob: nil)
      explain_code_available = blob ? blob_explain_code_available?(project) : tree_explain_code_available?(project)
      workspace_data = blob ? vue_blob_workspace_data : vue_tree_workspace_data

      super.merge(
        kerberos_url: alternative_kerberos_url? ? project.kerberos_url_to_repo : '',
        explain_code_available: explain_code_available.to_s
      ).merge(workspace_data)
    end

    override :web_ide_button_data
    def web_ide_button_data(options = {})
      super.merge({
        project_id: project_to_use.id
      }.merge(vue_tree_workspace_data))
    end

    private

    def tree_explain_code_available?(project)
      return false unless current_user

      if ::Feature.enabled?(:dap_external_trigger_usage_billing, current_user)
        current_user.allowed_to_use?(:duo_chat)
      else
        ::Gitlab::Llm::DuoChat.new(user: current_user, container: project).enabled_for_container?
      end
    end
  end
end
