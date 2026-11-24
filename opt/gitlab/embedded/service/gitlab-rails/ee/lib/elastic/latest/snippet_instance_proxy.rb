# frozen_string_literal: true

module Elastic
  module Latest
    class SnippetInstanceProxy < ApplicationInstanceProxy
      PROJECT_ACCESS_FIELDS_MIGRATION = :add_project_visibility_level_to_snippets
      ORGANIZATION_FIELDS_MIGRATION = :add_organization_fields_to_main_index
      HIDDEN_FIELD_MIGRATION = :add_hidden_to_snippets

      # Schema version. The format is YYVV (year/version).
      # YY is the two-digit year, VV is the version number (01-99) within that year.
      # Maps each version to the migration that must have finished for the fields it
      # introduced to be written. Please update if you're changing the schema of the document.
      SCHEMA_VERSIONS = {
        26_04 => HIDDEN_FIELD_MIGRATION,
        26_03 => ORGANIZATION_FIELDS_MIGRATION,
        26_02 => PROJECT_ACCESS_FIELDS_MIGRATION,
        26_01 => nil
      }.freeze
      SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max

      def as_indexed_json(options = {})
        # We don't use as_json(only: ...) because it calls all virtual and serialized attributes
        # https://gitlab.com/gitlab-org/gitlab/issues/349
        data = {}

        [
          :id,
          :title,
          :description,
          :created_at,
          :updated_at,
          :project_id,
          :author_id,
          :visibility_level
        ].each do |attr|
          data[attr.to_s] = safely_read_attribute_for_elasticsearch(attr)
        end

        data.merge!(build_project_access_data)
        data.merge!(build_organization_data)
        data.merge!(build_hidden_data)
        data['schema_version'] = schema_version

        data.merge(generic_attributes)
      end

      def es_parent
        nil
      end

      private

      def build_project_access_data
        return {} unless target.project && migration_finished?(PROJECT_ACCESS_FIELDS_MIGRATION)

        {
          'project_visibility_level' => target.project.visibility_level,
          'snippets_access_level' => safely_read_project_feature_for_elasticsearch(:snippets)
        }
      end

      # Snippets carry no `traversal_ids`, so no `organization_traversal_ids` either.
      # A personal snippet owns its `organization_id`; a project snippet leaves the
      # column NULL and resolves the owning organization through its project.
      def build_organization_data
        return {} unless migration_finished?(ORGANIZATION_FIELDS_MIGRATION)

        { 'organization_id' => target.organization_id || target.project&.organization_id }
      end

      def build_hidden_data
        return {} unless migration_finished?(HIDDEN_FIELD_MIGRATION)

        # `snippets.author_id` has no foreign key, so an orphaned snippet must still index.
        { 'hidden' => !!target.author&.banned? }
      end

      def schema_version
        highest_available_schema_version(SCHEMA_VERSIONS)
      end
    end
  end
end
