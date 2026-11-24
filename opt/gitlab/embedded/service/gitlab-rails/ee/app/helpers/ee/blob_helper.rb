# frozen_string_literal: true

module EE
  module BlobHelper
    extend ::Gitlab::Utils::Override

    override :vue_blob_header_app_data
    def vue_blob_header_app_data(project, blob, ref)
      super.merge(vue_blob_workspace_data)
    end

    override :vue_blob_app_data
    def show_duo_workflow_action?(blob)
      return false unless current_user.present?

      return false unless blob.project&.duo_remote_flows_enabled

      ::Gitlab::FileDetector.type_of(blob.name) == :jenkinsfile && blob.project.duo_features_enabled
    end

    def vue_blob_app_data(project, blob, ref)
      super.merge(explain_code_available: blob_explain_code_available?(project).to_s)
    end

    private

    def blob_explain_code_available?(project)
      return false unless current_user

      if ::Feature.enabled?(:dap_external_trigger_usage_billing, current_user)
        current_user.allowed_to_use?(:duo_chat)
      else
        ::Gitlab::Llm::DuoChat.new(user: current_user, container: project).enabled_for_container?
      end
    end
  end
end
