# frozen_string_literal: true

module Elastic
  module Latest
    class MergeRequestInstanceProxy < ApplicationInstanceProxy
      ORGANIZATION_FIELDS_MIGRATION = :add_organization_fields_to_merge_requests

      # Schema version. The format is YYVV (year/version).
      # YY is the two-digit year, VV is the version number (01-99) within that year.
      # Maps each version to the migration that must have finished for the fields it
      # introduced to be written. Please update if you're changing the schema of the document.
      SCHEMA_VERSIONS = {
        26_02 => ORGANIZATION_FIELDS_MIGRATION,
        26_01 => nil
      }.freeze
      SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max

      def as_indexed_json(_options = {})
        # We don't use as_json(only: ...) because it calls all virtual and serialized attributtes
        # https://gitlab.com/gitlab-org/gitlab/issues/349
        data = {}

        [
          :id,
          :iid,
          :target_branch,
          :source_branch,
          :title,
          :description,
          :created_at,
          :updated_at,
          :state,
          :merge_status,
          :source_project_id,
          :target_project_id,
          :project_id, # Redundant field aliased to target_project_id makes it easier to share searching code
          :author_id
        ].each do |attr|
          data[attr.to_s] = safely_read_attribute_for_elasticsearch(attr)
        end

        data['visibility_level'] = target.project.visibility_level
        data['merge_requests_access_level'] = safely_read_project_feature_for_elasticsearch(:merge_requests)
        data['hashed_root_namespace_id'] = target_project.namespace.hashed_root_namespace_id

        data['hidden'] = target.hidden?
        data['archived'] = target.project.self_or_ancestors_archived?

        data['schema_version'] = schema_version
        data['label_ids'] = target.label_ids.map(&:to_s)
        data['traversal_ids'] = target.project.elastic_namespace_ancestry

        data['assignee_ids'] = target.assignee_ids.map(&:to_s)

        data.merge!(build_organization_data)

        data.merge(generic_attributes)
      end

      private

      def build_organization_data
        return {} unless migration_finished?(ORGANIZATION_FIELDS_MIGRATION)

        build_organization_fields(target.project).stringify_keys
      end

      def schema_version
        highest_available_schema_version(SCHEMA_VERSIONS)
      end
    end
  end
end
