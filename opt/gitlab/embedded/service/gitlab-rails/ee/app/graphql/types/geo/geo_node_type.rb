# frozen_string_literal: true

module Types
  module Geo
    class GeoNodeType < BaseObject
      graphql_name 'GeoNode'

      authorize :read_geo_node
      authorize_granular_token permissions: :read_geo_node, boundary: :instance, boundary_type: :instance,
        assignable_when: [:admin]

      field :abuse_report_upload_registries, ::Types::Geo::AbuseReportUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::AbuseReportUploadRegistriesResolver,
        description: 'Find Abuse Report Upload registries on this Geo node. ' \
                    'Ignored if `geo_abuse_report_upload_replication` feature flag is disabled.',
        experiment: { milestone: '18.10' }
      field :achievement_upload_registries, ::Types::Geo::AchievementUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::AchievementUploadRegistriesResolver,
        description: 'Find Achievement Upload registries on this Geo node. ' \
                     'Ignored if `geo_achievement_upload_replication` feature flag is disabled.',
        experiment: { milestone: '18.11' }
      field :alert_management_metric_image_upload_registries, ::Types::Geo::AlertManagementMetricImageUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::AlertManagementMetricImageUploadRegistriesResolver,
        description: 'Find Alert Management Metric Image Upload registries on this Geo node. ' \
                     'Ignored if `geo_alert_management_metric_image_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :appearance_upload_registries, ::Types::Geo::AppearanceUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::AppearanceUploadRegistriesResolver,
        description: 'Find Appearance Upload registries on this Geo node. ' \
                     'Ignored if `geo_appearance_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.2' }
      field :bulk_import_export_upload_upload_registries, ::Types::Geo::BulkImportExportUploadUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::BulkImportExportUploadUploadRegistriesResolver,
        description: 'Find bulk import/export archive upload registries on this Geo node. ' \
                     'Ignored if `geo_bulk_import_export_upload_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.0' }
      field :checksum_mismatch_report_threshold, GraphQL::Types::Int, null: true, description: 'Number of consecutive checksum mismatches on a secondary before it reports the resource to the primary for self-heal re-verification.'
      field :checksum_mismatch_self_heal_cooldown_minutes, GraphQL::Types::Int, null: true, description: 'Minimum time (in minutes) between self-heal re-verification triggers for the same resource on the primary.'
      field :ci_secure_file_registries, ::Types::Geo::CiSecureFileRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::CiSecureFileRegistriesResolver,
        description: 'Find Ci Secure File registries on this Geo node'
      field :container_repositories_max_capacity, GraphQL::Types::Int, null: true, description: 'Maximum concurrency of container repository sync for the secondary node.'
      field :container_repository_registries, ::Types::Geo::ContainerRepositoryRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ContainerRepositoryRegistriesResolver,
        description: 'Find Container Repository registries on this Geo node.'
      field :dependency_list_export_part_upload_registries, ::Types::Geo::DependencyListExportPartUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::DependencyListExportPartUploadRegistriesResolver,
        description: 'Find Dependency List Export Part Upload registries on this Geo node. ' \
                     'Ignored if `geo_dependency_list_export_part_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.2' }
      field :dependency_list_export_upload_registries, ::Types::Geo::DependencyListExportUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::DependencyListExportUploadRegistriesResolver,
        description: 'Find Dependency List Export Upload registries on this Geo node. ' \
                     'Ignored if `geo_dependency_list_export_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :dependency_proxy_blob_registries, ::Types::Geo::DependencyProxyBlobRegistryType.connection_type,
        null: true,
        experiment: { milestone: '15.6' },
        resolver: ::Resolvers::Geo::DependencyProxyBlobRegistriesResolver,
        description: 'Find Dependency Proxy Blob registries on this Geo node.'
      field :dependency_proxy_manifest_registries, ::Types::Geo::DependencyProxyManifestRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::DependencyProxyManifestRegistriesResolver,
        description: 'Find Dependency Proxy Manifest registries on this Geo node.'
      field :design_management_action_upload_registries, ::Types::Geo::DesignManagementActionUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::DesignManagementActionUploadRegistriesResolver,
        description: 'Find Design Management Action Upload registries on this Geo node. ' \
                      'Ignored if `geo_design_management_action_upload_replication` feature flag is disabled.',
        experiment: { milestone: '18.11' }
      field :design_management_repository_registries, ::Types::Geo::DesignManagementRepositoryRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::DesignManagementRepositoryRegistriesResolver,
        description: 'Find Design Management Repository registries on this Geo node.',
        experiment: { milestone: '16.1' }
      field :enabled, GraphQL::Types::Boolean, null: true, description: 'Indicates whether the Geo node is enabled.'
      field :files_max_capacity, GraphQL::Types::Int, null: true, description: 'Maximum concurrency of LFS/attachment backfill for the secondary node.'
      field :group_upload_registries, ::Types::Geo::GroupUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::GroupUploadRegistriesResolver,
        description: 'Find Group Upload registries on this Geo node. ' \
                     'Ignored if `geo_group_upload_replication` feature flag is disabled.',
        experiment: { milestone: '18.11' }
      field :group_wiki_repository_registries, ::Types::Geo::GroupWikiRepositoryRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::GroupWikiRepositoryRegistriesResolver,
        description: 'Find group wiki repository registries on this Geo node.'
      field :id, GraphQL::Types::ID, null: false, description: 'ID of the GeoNode.'
      field :import_export_upload_upload_registries, ::Types::Geo::ImportExportUploadUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ImportExportUploadUploadRegistriesResolver,
        description: 'Find import/export archive upload registries on this Geo node. ' \
                     'Ignored if `geo_import_export_upload_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.0' }
      field :internal_url, GraphQL::Types::String, null: true, description: 'URL defined on the primary node secondary nodes should use to contact it.'
      field :issuable_metric_image_upload_registries, ::Types::Geo::IssuableMetricImageUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::IssuableMetricImageUploadRegistriesResolver,
        description: 'Find Issuable Metric Image Upload registries on this Geo node. ' \
                     'Ignored if `geo_issuable_metric_image_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :job_artifact_registries, ::Types::Geo::JobArtifactRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::JobArtifactRegistriesResolver,
        description: 'Find Job Artifact registries on this Geo node.'
      field :lfs_object_registries, ::Types::Geo::LfsObjectRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::LfsObjectRegistriesResolver,
        description: 'Find LFS object registries on this Geo node.'
      field :merge_request_diff_registries, ::Types::Geo::MergeRequestDiffRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::MergeRequestDiffRegistriesResolver,
        description: 'Find merge request diff registries on this Geo node.'
      field :minimum_reverification_interval, GraphQL::Types::Int, null: true, description: 'Interval (in days) in which the repository verification is valid. After expiry, it is reverted.'
      field :name, GraphQL::Types::String, null: true, description: 'Unique identifier for the Geo node.'
      field :organization_detail_upload_registries, ::Types::Geo::OrganizationDetailUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::OrganizationDetailUploadRegistriesResolver,
        description: 'Find Organization Detail Upload registries on this Geo node. ' \
                     'Ignored if `geo_organization_detail_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.2' }
      field :package_file_registries, ::Types::Geo::PackageFileRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PackageFileRegistriesResolver,
        description: 'Package file registries of the GeoNode.'
      field :packages_debian_project_component_file_registries, ::Types::Geo::PackagesDebianProjectComponentFileRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PackagesDebianProjectComponentFileRegistriesResolver,
        description: 'Find Debian Project Component File registries on this Geo node. ' \
                     'Ignored if `geo_packages_debian_project_component_file_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :packages_helm_metadata_cache_registries, ::Types::Geo::PackagesHelmMetadataCacheRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PackagesHelmMetadataCacheRegistriesResolver,
        description: 'Find Helm Metadata Cache registries on this Geo node. ' \
                     'Ignored if `geo_packages_helm_metadata_cache_replication` feature flag is disabled.'
      field :packages_nuget_symbol_registries, ::Types::Geo::PackagesNugetSymbolRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PackagesNugetSymbolRegistriesResolver,
        description: 'Find Packages::Nuget::Symbols registries on this Geo node. ' \
                     'Ignored if `geo_packages_nuget_symbol_replication` feature flag is disabled.'
      field :pages_deployment_registries, ::Types::Geo::PagesDeploymentRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PagesDeploymentRegistriesResolver,
        description: 'Find Pages Deployment registries on this Geo node'
      field :personal_snippet_upload_registries, ::Types::Geo::PersonalSnippetUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PersonalSnippetUploadRegistriesResolver,
        description: 'Find Personal Snippet Upload registries on this Geo node. ' \
                     'Ignored if `geo_personal_snippet_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :pipeline_artifact_registries, ::Types::Geo::PipelineArtifactRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::PipelineArtifactRegistriesResolver,
        description: 'Find pipeline artifact registries on this Geo node.'
      field :primary, GraphQL::Types::Boolean, null: true, description: 'Indicates whether the Geo node is the primary.'
      field :project_import_export_relation_export_upload_upload_registries, ::Types::Geo::ProjectImportExportRelationExportUploadUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ProjectImportExportRelationExportUploadUploadRegistriesResolver,
        description: 'Find Relation Export File Upload registries on this Geo node. ' \
                     'Ignored if `geo_project_import_export_relation_export_upload_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.0' }
      field :project_repository_registries, ::Types::Geo::ProjectRepositoryRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ProjectRepositoryRegistriesResolver,
        description: 'Find Project registries on this Geo node. ' \
                     'Ignored if `geo_project_repository_replication` feature flag is disabled.'
      field :project_topic_upload_registries, ::Types::Geo::ProjectTopicUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ProjectTopicUploadRegistriesResolver,
        description: 'Find Project Topic Upload registries on this Geo node. ' \
                     'Ignored if `geo_project_topic_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.2' }
      field :project_upload_registries, ::Types::Geo::ProjectUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ProjectUploadRegistriesResolver,
        description: 'Find Project Upload registries on this Geo node. ' \
                      'Ignored if `geo_project_upload_replication` feature flag is disabled.',
        experiment: { milestone: '18.10' }
      field :project_wiki_repository_registries, ::Types::Geo::ProjectWikiRepositoryRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::ProjectWikiRepositoryRegistriesResolver,
        description: 'Find Project Wiki Repository registries on this Geo node. ' \
                     'Ignored if `geo_project_wiki_repository_replication` feature flag is disabled.'
      field :repos_max_capacity, GraphQL::Types::Int, null: true, description: 'Maximum concurrency of repository backfill for the secondary node.'
      field :selective_sync_namespaces, ::Types::NamespaceType.connection_type, null: true, method: :namespaces, description: 'Namespaces that should be synced, if `selective_sync_type` == `namespaces`.'
      field :selective_sync_shards, type: [GraphQL::Types::String], null: true, description: 'Repository storages whose projects should be synced, if `selective_sync_type` == `shards`.'
      field :selective_sync_type, GraphQL::Types::String, null: true, description: 'Indicates if syncing is limited to only specific groups, or shards.'
      field :snippet_repository_registries, ::Types::Geo::SnippetRepositoryRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::SnippetRepositoryRegistriesResolver,
        description: 'Find snippet repository registries on this Geo node.'
      field :sync_object_storage, GraphQL::Types::Boolean, null: true, description: 'Indicates if the secondary node will replicate blobs in Object Storage.'
      field :terraform_state_version_registries, ::Types::Geo::TerraformStateVersionRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::TerraformStateVersionRegistriesResolver,
        description: 'Find terraform state version registries on this Geo node.'
      field :upload_registries, ::Types::Geo::UploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::UploadRegistriesResolver,
        description: 'Find Upload registries on this Geo node'
      field :url, GraphQL::Types::String, null: true, description: 'User-facing URL for the Geo node.'
      field :user_permission_export_upload_upload_registries, ::Types::Geo::UserPermissionExportUploadUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::UserPermissionExportUploadUploadRegistriesResolver,
        description: 'Find User Permission Export File Upload registries on this Geo node. ' \
                     'Ignored if `geo_user_permission_export_upload_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :user_upload_registries, ::Types::Geo::UserUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::UserUploadRegistriesResolver,
        description: 'Find User Upload registries on this Geo node. ' \
                     'Ignored if `geo_user_upload_replication` feature flag is disabled.',
        experiment: { milestone: '18.11' }
      field :verification_max_capacity, GraphQL::Types::Int, null: true, description: 'Maximum concurrency of repository verification for the secondary node.'
      field :vulnerability_archive_export_upload_registries, ::Types::Geo::VulnerabilityArchiveExportUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::VulnerabilityArchiveExportUploadRegistriesResolver,
        description: 'Find Vulnerability Archive Export Upload registries on this Geo node. ' \
                     'Ignored if `geo_vulnerability_archive_export_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.0' }
      field :vulnerability_export_part_upload_registries, ::Types::Geo::VulnerabilityExportPartUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::VulnerabilityExportPartUploadRegistriesResolver,
        description: 'Find Vulnerability Export Part Upload registries on this Geo node. ' \
                     'Ignored if `geo_vulnerability_export_part_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.1' }
      field :vulnerability_export_upload_registries, ::Types::Geo::VulnerabilityExportUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::VulnerabilityExportUploadRegistriesResolver,
        description: 'Find Vulnerability Export Upload registries on this Geo node. ' \
                     'Ignored if `geo_vulnerability_export_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.0' }
      field :vulnerability_remediation_upload_registries, ::Types::Geo::VulnerabilityRemediationUploadRegistryType.connection_type,
        null: true,
        resolver: ::Resolvers::Geo::VulnerabilityRemediationUploadRegistriesResolver,
        description: 'Find Vulnerability Remediation Upload registries on this Geo node. ' \
                     'Ignored if `geo_vulnerability_remediation_upload_replication` feature flag is disabled.',
        experiment: { milestone: '19.2' }
    end
  end
end
