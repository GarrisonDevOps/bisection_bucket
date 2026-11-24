# frozen_string_literal: true

module Search
  module Elastic
    module References
      class WorkItem < Reference
        include Search::Elastic::Concerns::DatabaseReference

        ORGANIZATION_FIELDS_MIGRATION = :add_organization_fields_to_work_items

        # Schema version mappings. The format is YYVV (year/version).
        # YY is the two-digit year, VV is the version number (01-99) within that year.
        # Maps schema versions to their corresponding migration names.
        # Set migration to nil for baseline versions that don't require migration completion.
        # The schema_version method dynamically selects the highest version whose migration
        # has completed (or nil), preventing indexing with incomplete schema changes.
        SCHEMA_VERSIONS = {
          26_03 => ORGANIZATION_FIELDS_MIGRATION,
          26_02 => :add_title_keyword_to_work_items,
          25_44 => nil
        }.freeze

        # Backwards compatibility constant - returns the latest schema version available.
        # This maintains compatibility with existing code that references SCHEMA_VERSION.
        SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max

        DEFAULT_INDEX_ATTRIBUTES = %i[
          id
          iid
          created_at
          updated_at
          title
          description
          author_id
          due_date
          confidential
          project_id
          state
        ].freeze

        PERMITTED_FILTER_KEYS = %i[
          order_by
          sort
          confidential
          state
          label_name
          label_names
          not_label_names
          or_label_names
          none_label_names
          any_label_names
          include_archived
          fields
          author_username
          not_author_username
          milestone_title
          not_milestone_title
          none_milestones
          any_milestones
          milestone_state_filters
          assignee_ids
          not_assignee_ids
          or_assignee_ids
          none_assignees
          any_assignees
          weight
          not_weight
          none_weight
          any_weight
          work_item_type_ids
          health_status
          not_health_status
          none_health_status
          any_health_status
        ].freeze

        DOC_TYPE = 'work_item'

        override :serialize
        def self.serialize(record)
          new(record.id, record.es_parent).serialize
        end

        override :instantiate
        def self.instantiate(string)
          _, id, routing = delimit(string)

          # this puts the record in the work items index
          new(id, routing)
        end

        override :preload_indexing_data
        def self.preload_indexing_data(refs)
          ids = refs.map(&:identifier)

          records = ::WorkItem.id_in(ids).preload_indexing_data
          records_by_id = records.index_by(&:id)

          refs.each do |ref|
            ref.database_record = records_by_id[ref.identifier.to_i]
          end

          refs
        end

        def self.index
          environment_specific_index_name('work_items')
        end

        def self.model_klass
          ::WorkItem
        end

        attr_reader :identifier, :routing

        def initialize(identifier, routing)
          @identifier = identifier.to_i
          @routing = routing
        end

        def schema_version
          SCHEMA_VERSIONS.sort.reverse_each do |version, migration|
            break version if migration.nil? || ::Elastic::DataMigrationService.migration_has_finished?(migration)
          end
        end

        override :serialize
        def serialize
          self.class.join_delimited([klass, identifier, routing].compact)
        end

        override :operation
        def operation
          database_record ? :upsert : :delete
        end

        override :as_indexed_json
        def as_indexed_json
          validate_record!(database_record)
          build_indexed_json(database_record)
        end

        override :index_name
        def index_name
          self.class.index
        end

        private

        def validate_record!(record)
          return unless record.namespace.nil? || record.namespace.root_ancestor.nil?

          raise ::Elastic::Latest::DocumentShouldBeDeletedFromIndexError.new(record.class.name, record.id)
        end

        def build_indexed_json(target)
          data = {}

          DEFAULT_INDEX_ATTRIBUTES.each do |attribute|
            data[attribute.to_s] = safely_read_attribute_for_elasticsearch(target, attribute)
          end

          data.merge!(build_extra_data(target))
          data.merge!(build_organization_data(target))
          data.merge!(build_namespace_data(target))
          data.merge!(build_project_data(target))
          data.merge!(build_milestone_data(target))

          data.stringify_keys
        end

        def build_extra_data(target)
          extra_data = {
            label_ids: target.label_ids.map(&:to_s),
            hidden: target.hidden?,
            root_namespace_id: target.namespace.root_ancestor.id,
            traversal_ids: target.namespace.elastic_namespace_ancestry,
            hashed_root_namespace_id: target.namespace.hashed_root_namespace_id,
            work_item_type_id: target.work_item_type_id,
            assignee_id: safely_read_attribute_for_elasticsearch(target, :issue_assignee_user_ids),
            upvotes: target.upvotes_count,
            schema_version: schema_version,
            routing: routing,
            type: model_klass.es_type
          }

          extra_data['closed_at'] = target.closed_at
          extra_data['weight'] = target.weight
          extra_data['health_status'] = target.health_status_for_database
          extra_data['label_names'] = target.labels&.map(&:title)

          extra_data
        end

        def build_organization_data(target)
          return {} unless ::Elastic::DataMigrationService.migration_has_finished?(ORGANIZATION_FIELDS_MIGRATION)

          namespace = target.namespace

          {
            organization_id: namespace.organization_id,
            organization_traversal_ids: ::Search.organization_traversal_ids(
              namespace.organization_id, namespace.elastic_namespace_ancestry
            )
          }
        end

        def build_namespace_data(target)
          return {} unless target.namespace.group_namespace?

          {
            namespace_visibility_level: target.namespace.visibility_level,
            namespace_id: target.namespace_id
          }
        end

        def build_project_data(target)
          return {} unless target.project.present?

          {
            archived: target.project.self_or_ancestors_archived?,
            project_visibility_level: target.project.visibility_level,
            issues_access_level: target.project.issues_access_level
          }
        end

        def build_milestone_data(target)
          milestone_data = {
            milestone_title: target.milestone&.title,
            milestone_id: target.milestone_id
          }

          milestone_data['milestone_start_date'] = target.milestone&.start_date
          milestone_data['milestone_due_date'] = target.milestone&.due_date
          milestone_data['milestone_state'] = target.milestone&.state

          milestone_data
        end
      end
    end
  end
end
