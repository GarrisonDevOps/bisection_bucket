# frozen_string_literal: true

class AddDuoWorkflowFileAttachmentsEnabledToNamespaceAiSettings < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :namespace_ai_settings, :duo_workflow_file_attachments_enabled, :boolean, default: false, null: false
  end
end
