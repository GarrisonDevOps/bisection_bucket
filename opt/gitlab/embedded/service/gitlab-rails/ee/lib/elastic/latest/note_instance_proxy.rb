# frozen_string_literal: true

module Elastic
  module Latest
    class NoteInstanceProxy < ApplicationInstanceProxy
      # Writes gate on the mapping: the notes index is `dynamic: 'strict'`, so
      # a field cannot be indexed before its mapping exists.
      HIDDEN_FIELD_MIGRATION = :add_hidden_to_notes
      ORGANIZATION_FIELDS_MIGRATION = :add_organization_fields_to_notes

      # Reads gate on the backfill instead -- see `NoteClassProxy#hidden_filter`.
      HIDDEN_BACKFILL_MIGRATION = :backfill_hidden_on_notes

      # Schema version. The format is YYVV (year/version).
      # YY is the two-digit year, VV is the version number (01-99) within that year.
      # Maps each version to the migration that must have finished for the fields it
      # introduced to be written. Please update if you're changing the schema of the document.
      SCHEMA_VERSIONS = {
        26_03 => ORGANIZATION_FIELDS_MIGRATION,
        26_02 => HIDDEN_FIELD_MIGRATION,
        25_24 => nil
      }.freeze
      SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max

      # We're migrating the `confidential` Note column to `internal` and therefore write to both attributes.
      # https://gitlab.com/groups/gitlab-org/-/epics/9634
      DEFAULT_INDEX_ATTRIBUTES = %i[
        id note project_id noteable_type noteable_id created_at updated_at confidential internal
      ].freeze

      delegate :noteable, to: :target

      def as_indexed_json(_options = {})
        # `noteable` can be sometimes be nil (eg. when a commit has been
        # deleted) or somehow it was left orphaned in the database. In such
        # cases we want to delete it from the index since there is no value in
        # having orphaned notes be searchable.
        raise Elastic::Latest::DocumentShouldBeDeletedFromIndexError.new(target.class.name, target.id) if noteable.nil?

        data = {}

        # We don't use as_json(only: ...) because it calls all virtual and serialized attributes
        # https://gitlab.com/gitlab-org/gitlab/issues/349
        DEFAULT_INDEX_ATTRIBUTES.each do |attr|
          data[attr] = safely_read_attribute_for_elasticsearch(attr)
        end

        data.merge!(build_issue_data)
        data.merge!(build_traversal_ids)
        data.merge!(build_project_data)
        data.merge!(build_visibility_data)
        data.merge!(build_hidden_data)
        data.merge!(build_organization_data)
        data.merge!(build_project_feature_access_level_data)
        data.merge!(build_schema_version)
        data.merge!(generic_attributes)

        data.deep_stringify_keys
      end

      private

      def build_visibility_data
        {
          visibility_level: target.project&.visibility_level || Gitlab::VisibilityLevel::PRIVATE
        }
      end

      def build_hidden_data
        return {} unless migration_finished?(HIDDEN_FIELD_MIGRATION)

        { hidden: target.hidden? }
      end

      def build_organization_data
        return {} unless migration_finished?(ORGANIZATION_FIELDS_MIGRATION)

        namespace = indexed_namespace
        return {} if namespace.nil?

        build_organization_fields(namespace)
      end

      def build_project_feature_access_level_data
        # other note types (DesignManagement::Design, AlertManagement::Alert, Epic, Vulnerability )
        # are indexed but not currently searchable so we will not add permission
        # data for them until the search capability is implemented
        case noteable
        when Snippet
          { snippets_access_level: safely_read_project_feature_for_elasticsearch(:snippets) }
        when Commit
          { repository_access_level: safely_read_project_feature_for_elasticsearch(:repository) }
        when Issue, MergeRequest
          access_level_attribute = ProjectFeature.access_level_attribute(noteable)

          { access_level_attribute.to_s => safely_read_project_feature_for_elasticsearch(noteable) }
        else
          {}
        end
      end

      def build_project_data
        return {} unless target.project

        {
          hashed_root_namespace_id: target.project.namespace&.hashed_root_namespace_id,
          archived: target.project.self_or_ancestors_archived?
        }
      end

      def build_issue_data
        return {} unless noteable.is_a?(Issue)

        {
          issue: {
            assignee_id: noteable.assignee_ids,
            author_id: noteable.author_id,
            confidential: noteable.confidential
          }
        }
      end

      def build_traversal_ids
        namespace = indexed_namespace

        return {} if namespace.nil?

        {
          traversal_ids: namespace.elastic_namespace_ancestry
        }
      end

      def indexed_namespace
        noteable.try(:namespace) ||
          noteable.try(:project)&.try(:namespace) ||
          noteable.try(:target_project)&.try(:namespace)
      end

      def build_schema_version
        {
          schema_version: schema_version
        }
      end

      def schema_version
        highest_available_schema_version(SCHEMA_VERSIONS)
      end
    end
  end
end
