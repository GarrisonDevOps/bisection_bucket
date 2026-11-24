# frozen_string_literal: true

module Elastic
  module Latest
    class MilestoneInstanceProxy < ApplicationInstanceProxy
      extend ::Gitlab::Utils::Override

      ORGANIZATION_FIELDS_MIGRATION = :add_organization_fields_to_main_index

      # Schema version. The format is YYVV (year/version).
      # YY is the two-digit year, VV is the version number (01-99) within that year.
      # Maps each version to the migration that must have finished for the fields it
      # introduced to be written. Please update if you're changing the schema of the document.
      SCHEMA_VERSIONS = {
        26_02 => ORGANIZATION_FIELDS_MIGRATION,
        26_01 => nil
      }.freeze
      SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max

      DEFAULT_INDEX_ATTRIBUTES = %i[
        id
        iid
        title
        description
        project_id
        created_at
        updated_at
      ].freeze

      override :es_parent
      def es_parent
        return super if target.project_id

        "n_#{target.group.traversal_ids.first}"
      end

      def as_indexed_json(_options = {})
        data = {}

        DEFAULT_INDEX_ATTRIBUTES.each do |attribute|
          data[attribute.to_s] = safely_read_attribute_for_elasticsearch(attribute)
        end

        data.merge!(build_extra_data)
        data.merge!(build_project_data(target))
        data.merge!(build_group_data(target))

        data.merge(generic_attributes).stringify_keys
      end

      private

      def build_extra_data
        {
          schema_version: schema_version
        }
      end

      def schema_version
        highest_available_schema_version(SCHEMA_VERSIONS)
      end

      def build_organization_data(container)
        return {} unless migration_finished?(ORGANIZATION_FIELDS_MIGRATION)

        build_organization_fields(container)
      end

      def build_project_data(target)
        return {} unless target.project.present?

        {
          archived: target.project.self_or_ancestors_archived?,
          visibility_level: target.project.visibility_level,
          issues_access_level: safely_read_project_feature_for_elasticsearch(:issues),
          merge_requests_access_level: safely_read_project_feature_for_elasticsearch(:merge_requests),
          traversal_ids: target.project.elastic_namespace_ancestry
        }.merge(build_organization_data(target.project))
      end

      def build_group_data(target)
        return {} unless target.group.present?

        {
          namespace_id: target.group_id,
          archived: target.group.self_or_ancestors_archived?,
          visibility_level: target.group.visibility_level,
          traversal_ids: target.group.elastic_namespace_ancestry
        }.merge(build_organization_data(target.group))
      end
    end
  end
end
