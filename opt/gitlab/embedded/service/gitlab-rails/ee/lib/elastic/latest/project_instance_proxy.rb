# frozen_string_literal: true

module Elastic
  module Latest
    class ProjectInstanceProxy < ApplicationInstanceProxy
      extend ::Gitlab::Utils::Override

      ORGANIZATION_FIELDS_MIGRATION = :add_organization_fields_to_projects

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
        # We don't use as_json(only: ...) because it calls all virtual and serialized attributes
        # https://gitlab.com/gitlab-org/gitlab/issues/349
        data = {}

        [
          :id,
          :name,
          :path,
          :description,
          :namespace_id,
          :created_at,
          :updated_at,
          :visibility_level,
          :last_activity_at,
          :name_with_namespace,
          :path_with_namespace,
          :star_count
        ].each do |attr|
          data[attr.to_s] = safely_read_attribute_for_elasticsearch(attr)
        end

        # ES6 is now single-type per index, so we implement our own typing
        data['type'] = 'project'

        data['schema_version'] = schema_version

        data['traversal_ids'] = target.elastic_namespace_ancestry

        data.merge!(build_organization_data)

        data['ci_catalog'] = target.catalog_resource.present?

        data['last_repository_updated_date'] = target.last_repository_updated_at

        data['mirror'] = target.mirror?
        data['forked'] = target.forked? || false
        data['owner_id'] = target.owner&.id
        data['repository_languages'] = target.repository_languages.map(&:name)
        data['archived'] = target.self_or_ancestors_archived?

        data
      end

      override :es_parent
      def es_parent
        "n_#{target.root_ancestor.id}"
      end

      private

      def build_organization_data
        return {} unless migration_finished?(ORGANIZATION_FIELDS_MIGRATION)

        build_organization_fields(target).stringify_keys
      end

      def schema_version
        highest_available_schema_version(SCHEMA_VERSIONS)
      end
    end
  end
end
