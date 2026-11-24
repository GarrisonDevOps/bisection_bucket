# frozen_string_literal: true

class AddBlobLocationToBlobRegistries < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

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
    file_registry
    group_upload_registry
    import_export_upload_upload_registry
    issuable_metric_image_upload_registry
    organization_detail_upload_registry
    personal_snippet_upload_registry
    project_import_export_relation_export_upload_upload_registry
    project_topic_upload_registry
    project_upload_registry
    user_permission_export_upload_upload_registry
    user_upload_registry
    vulnerability_archive_export_upload_registry
    vulnerability_export_part_upload_registry
    vulnerability_export_upload_registry
    vulnerability_remediation_upload_registry
  ].freeze

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
    file_registry
    group_upload_registry
    import_export_upload_upload_registry
    issuable_metric_image_upload_registry
    job_artifact_registry
    lfs_object_registry
    merge_request_diff_registry
    organization_detail_upload_registry
    package_file_registry
    packages_debian_project_component_file_registry
    packages_helm_metadata_cache_registry
    packages_nuget_symbol_registry
    pages_deployment_registry
    personal_snippet_upload_registry
    pipeline_artifact_registry
    project_import_export_relation_export_upload_upload_registry
    project_topic_upload_registry
    project_upload_registry
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

  # rubocop:disable Migration/AddLimitToTextColumns -- limits are added in post-deployment migrations
  def up
    TABLES.each do |table|
      with_lock_retries do
        add_column table, :blob_path, :text, if_not_exists: true
        add_column table, :uploader_class, :text, if_not_exists: true if UPLOAD_TABLES.include?(table)
      end
    end
  end
  # rubocop:enable Migration/AddLimitToTextColumns

  def down
    TABLES.each do |table|
      with_lock_retries do
        remove_column table, :blob_path, if_exists: true
        remove_column table, :uploader_class, if_exists: true if UPLOAD_TABLES.include?(table)
      end
    end
  end
end
