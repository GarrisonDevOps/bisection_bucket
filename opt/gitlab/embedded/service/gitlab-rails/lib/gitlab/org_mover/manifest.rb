# frozen_string_literal: true

module Gitlab
  module OrgMover
    # This cell's Org Mover manifest (orgmover.manifest.v1.Manifest as a Hash):
    # what a move must carry, generated from the table dictionary and live
    # columns for the running GitLab version. Ported from org-mover's
    # demo/cng/scripts/manifest.rb; keep the two in step.
    class Manifest
      Error = Class.new(StandardError)

      SERVICE_NAME = 'gitlab-rails'

      # Schemas whose tables hold an organization's rows; the manifest lists only what moves.
      MIGRATED_SCHEMAS = %w[gitlab_main_org gitlab_main_user gitlab_ci gitlab_sec].freeze

      # The Upload model's per-model_type partitions, all keyed by path. The parent
      # table, uploads, is cell-local and has no sharding key, so it never moves.
      UPLOADS_TABLES = %w[
        project_uploads namespace_uploads user_uploads snippet_uploads
        organization_detail_uploads project_topic_uploads design_management_action_uploads
        issuable_metric_image_uploads alert_management_alert_metric_image_uploads
        abuse_report_uploads achievement_uploads ai_vectorizable_file_uploads
        bulk_import_export_upload_uploads import_export_upload_uploads
        dependency_list_export_uploads dependency_list_export_part_uploads
        project_import_export_relation_export_upload_uploads user_permission_export_upload_uploads
        vulnerability_export_uploads vulnerability_export_part_uploads
        vulnerability_archive_export_uploads vulnerability_remediation_uploads
      ].freeze

      # Org Mover's object-storage handler registry. LFS stays out: the cell
      # cannot heal it yet (see EXCLUDED_TABLES).
      OBJECT_STORAGE = {
        'p_ci_job_artifacts' => %w[OBJECT_STORAGE_HANDLER_JOB_ARTIFACTS artifacts],
        'ci_pipeline_artifacts' => %w[OBJECT_STORAGE_HANDLER_PIPELINE_ARTIFACTS artifacts],
        'ci_secure_files' => %w[OBJECT_STORAGE_HANDLER_CI_SECURE_FILES ci-secure-files],
        'merge_request_diffs' => %w[OBJECT_STORAGE_HANDLER_EXTERNAL_DIFFS external-diffs],
        'terraform_state_versions' => %w[OBJECT_STORAGE_HANDLER_TERRAFORM_STATE terraform-state],
        'pages_deployments' => %w[OBJECT_STORAGE_HANDLER_PAGES pages],
        'dependency_proxy_blobs' => %w[OBJECT_STORAGE_HANDLER_DEPENDENCY_PROXY dependency-proxy],
        'dependency_proxy_manifests' => %w[OBJECT_STORAGE_HANDLER_DEPENDENCY_PROXY dependency-proxy],
        'packages_package_files' => %w[OBJECT_STORAGE_HANDLER_PACKAGES packages],
        'packages_nuget_symbols' => %w[OBJECT_STORAGE_HANDLER_PACKAGES_METADATA packages],
        'packages_helm_metadata_caches' => %w[OBJECT_STORAGE_HANDLER_PACKAGES_METADATA packages],
        'packages_npm_metadata_caches' => %w[OBJECT_STORAGE_HANDLER_PACKAGES_METADATA packages],
        'packages_rubygems_spec_files' => %w[OBJECT_STORAGE_HANDLER_PACKAGES_METADATA packages],
        'packages_debian_project_component_files' => %w[OBJECT_STORAGE_HANDLER_DEBIAN_PROJECT_COMPONENT_FILES packages],
        'packages_debian_group_component_files' => %w[OBJECT_STORAGE_HANDLER_DEBIAN_GROUP_COMPONENT_FILES packages]
      }.merge(UPLOADS_TABLES.index_with { |_table| %w[OBJECT_STORAGE_HANDLER_UPLOADS uploads] }).freeze

      # Org Mover's repository handler registry.
      GITALY = {
        'project_repositories' => 'GITALY_HANDLER_REPOSITORY',
        'project_wiki_repositories' => 'GITALY_HANDLER_PROJECT_WIKI_REPOSITORY',
        'design_management_repositories' => 'GITALY_HANDLER_DESIGN_REPOSITORY',
        'group_wiki_repositories' => 'GITALY_HANDLER_GROUP_WIKI_REPOSITORY',
        'snippet_repositories' => 'GITALY_HANDLER_SNIPPET_REPOSITORY'
      }.freeze

      # LFS link rows would land with lfs_object_id NULL and nothing would heal them.
      EXCLUDED_TABLES = %w[lfs_objects_projects].freeze

      SHARDING_KEYS = {
        'organizations' => 'SHARDING_KEY_ORGANIZATIONS',
        'namespaces' => 'SHARDING_KEY_NAMESPACES',
        'projects' => 'SHARDING_KEY_PROJECTS',
        'users' => 'SHARDING_KEY_USERS'
      }.freeze

      # The tables an unqualified name resolves to, as table_exists? sees them.
      # format_type keeps the [] of array types, which Column#sql_type drops.
      LIVE_COLUMNS_SQL = <<~SQL
        SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod)
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        WHERE c.relkind IN ('r', 'p')
          AND pg_table_is_visible(c.oid)
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY c.relname, a.attnum
      SQL

      def generate
        manifest = {
          service: SERVICE_NAME,
          siphon: { databases: siphon_databases },
          generated_at: Time.current.iso8601
        }

        manifest[:object_storage] = object_storage_section if object_sources.any?
        manifest[:gitaly] = gitaly_section if gitaly_sources.any?
        manifest
      end

      private

      def tables
        @tables ||= migrated_entries.filter_map do |entry|
          name = entry.table_name
          sharding_key = sharding_key_for(entry)
          next unless sharding_key

          connection_name = connection_name_for(entry.gitlab_schema)
          columns = live_columns(connection_name)[name]
          next if columns.blank?

          database_of[name] = database_for(connection_name)

          table = { table: name, sharding_key: sharding_key, columns: columns }
          ignore = ignore_predicates[name]
          table[:ignore] = ignore if ignore
          table
        end
      end

      def database_of
        @database_of ||= {}
      end

      # One catalog query per connection, not two per table: about 2,000
      # queries made a request slower than Org Mover's 10 s fetch timeout.
      def live_columns(connection_name)
        @live_columns ||= {}
        @live_columns[connection_name] ||= connection_for(connection_name)
          .select_rows(LIVE_COLUMNS_SQL)
          .group_by(&:first)
          .transform_values { |rows| rows.map { |_table, name, type| { name: name, type: type } } }
      end

      def table_names
        @table_names ||= tables.map { |table| table.fetch(:table) }
      end

      def siphon_databases
        tables.group_by { |table| database_of[table[:table]] }.sort.to_h.transform_values do |group|
          { type: 'SIPHON_DATABASE_TYPE_POSTGRESQL', tables: group }
        end
      end

      def object_sources
        @object_sources ||= OBJECT_STORAGE.select { |table, _| table_names.include?(table) }
          .map do |table, (handler, storage)|
            { database: { name: database_of[table], table: table }, handler: handler, storage: storage }
          end
      end

      def gitaly_sources
        @gitaly_sources ||= GITALY.select { |table, _| table_names.include?(table) }.map do |table, handler|
          { database: { name: database_of[table], table: table }, handler: handler }
        end
      end

      def object_storage_section
        {
          storages: object_sources.map { |source| source[:storage] }.uniq.sort.index_with { {} },
          sources: object_sources
        }
      end

      def gitaly_section
        {
          storages: ::Gitlab.config.repositories.storages.keys.map(&:to_s).index_with { {} },
          sources: gitaly_sources
        }
      end

      def migrated_entries
        ::Gitlab::Database::Dictionary.entries.select(&:table_name).sort_by(&:table_name).select do |entry|
          MIGRATED_SCHEMAS.include?(entry.gitlab_schema) && EXCLUDED_TABLES.exclude?(entry.table_name)
        end
      end

      # A sharding key pointing at an unsupported member table drops the whole
      # table: the cell could not scope its rows.
      def sharding_key_for(entry)
        return if entry.sharding_key.blank?

        key = {}
        entry.sharding_key.each do |column, table|
          member = SHARDING_KEYS[table.to_s]
          return nil unless member

          key[column.to_s] = member
        end

        key
      end

      # Raises when no connection owns a migrated schema: a guess could file
      # its tables under a database that does not hold them.
      def connection_name_for(schema)
        @connection_names ||= {}
        @connection_names[schema] ||= begin
          owner = ::Gitlab::Database.all_database_connections.each_value.find do |db|
            db.gitlab_schemas.include?(schema.to_sym)
          end

          raise Error, "no Rails connection owns gitlab_schema #{schema}" unless owner

          owner.name
        end
      end

      # A connection without its own physical database files under its
      # fallback's name; the cell config declares one database per physical one.
      def database_for(connection_name)
        info = ::Gitlab::Database.all_database_connections.fetch(connection_name)
        own = ::Gitlab::Database.has_database?(connection_name)

        "gitlab_#{own ? connection_name : (info.fallback_database || :main)}"
      end

      def connection_for(connection_name)
        (::Gitlab::Database.database_base_models[connection_name] || ApplicationRecord).connection
      end

      # Bot users and their personal namespaces are per-cell infrastructure;
      # moving the source's copies collides with the target's on usernames,
      # emails and routes.
      def ignore_predicates
        @ignore_predicates ||= begin
          bot_type_ids = ::HasUserType::BOT_USER_TYPES
            .map { |type| ::HasUserType::USER_TYPES.fetch(type) }.sort.join(',')

          {
            'users' => "user_type IN (#{bot_type_ids})",
            'namespaces' => "type = 'User' AND owner_id IN " \
              "(SELECT id FROM users WHERE user_type IN (#{bot_type_ids}))"
          }
        end
      end
    end
  end
end
