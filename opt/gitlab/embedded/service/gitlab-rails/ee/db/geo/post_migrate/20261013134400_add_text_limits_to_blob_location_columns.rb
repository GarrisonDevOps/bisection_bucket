# frozen_string_literal: true

class AddTextLimitsToBlobLocationColumns < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  # Post-deploy because validation scans each table; 1024 matches the object storage key limit.
  TABLES = %i[
    abuse_report_upload_registry
    achievement_upload_registry
    ai_vectorizable_file_upload_registry
    alert_management_metric_image_upload_registry
    appearance_upload_registry
    bulk_import_export_upload_upload_registry
    ci_secure_file_registry
    dependency_list_export_part_upload_registry
    dependency_list_export_upload_registry
    dependency_proxy_blob_registry
    dependency_proxy_manifest_registry
    design_management_action_upload_registry
    group_upload_registry
    import_export_upload_upload_registry
    issuable_metric_image_upload_registry
    organization_detail_upload_registry
    packages_debian_project_component_file_registry
    packages_helm_metadata_cache_registry
    packages_nuget_symbol_registry
    pages_deployment_registry
    personal_snippet_upload_registry
    pipeline_artifact_registry
    project_import_export_relation_export_upload_upload_registry
    project_topic_upload_registry
    supply_chain_attestation_registry
    terraform_state_version_registry
    user_permission_export_upload_upload_registry
    user_upload_registry
    virtual_registries_packages_maven_cache_remote_entry_registry
    vulnerability_archive_export_upload_registry
    vulnerability_export_part_upload_registry
    vulnerability_export_upload_registry
    vulnerability_remediation_upload_registry
  ].freeze

  UPLOAD_TABLES = %i[
    abuse_report_upload_registry
    achievement_upload_registry
    ai_vectorizable_file_upload_registry
    alert_management_metric_image_upload_registry
    appearance_upload_registry
    bulk_import_export_upload_upload_registry
    dependency_list_export_part_upload_registry
    dependency_list_export_upload_registry
    design_management_action_upload_registry
    group_upload_registry
    import_export_upload_upload_registry
    issuable_metric_image_upload_registry
    organization_detail_upload_registry
    personal_snippet_upload_registry
    project_import_export_relation_export_upload_upload_registry
    project_topic_upload_registry
    user_permission_export_upload_upload_registry
    user_upload_registry
    vulnerability_archive_export_upload_registry
    vulnerability_export_part_upload_registry
    vulnerability_export_upload_registry
    vulnerability_remediation_upload_registry
  ].freeze

  def up
    TABLES.each do |table|
      add_text_limit table, :blob_path, 1024
      add_text_limit table, :uploader_class, 255 if UPLOAD_TABLES.include?(table)
    end
  end

  def down
    TABLES.each do |table|
      remove_text_limit table, :blob_path
      remove_text_limit table, :uploader_class if UPLOAD_TABLES.include?(table)
    end
  end
end
