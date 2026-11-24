# frozen_string_literal: true

module Search
  module Elastic
    module References
      class Group < Reference
        include Search::Elastic::Concerns::DatabaseReference
        include Search::Elastic::Concerns::SchemaVersionedReference

        DOC_TYPE = 'group'
        INDEX_NAME = 'groups'

        # Fields that need a migration to be finished. Use #set_field to conditionally set a field value
        # depending on if the migration has completed.
        FIELDS_WITH_MIGRATIONS = {
          'active' => :add_active_to_groups,
          'organization_traversal_ids' => :add_organization_fields_to_groups
        }.freeze

        # Maps schema versions to their corresponding migration names.
        # Set migration to nil for baseline versions that don't require migration completion.
        SCHEMA_VERSIONS = {
          26_02 => nil,
          26_03 => FIELDS_WITH_MIGRATIONS['active'],
          26_04 => FIELDS_WITH_MIGRATIONS['organization_traversal_ids']
        }.freeze
        SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max.freeze

        DIRECT_FIELDS = %w[
          id
          name
          path
          description
          parent_id
          visibility_level
          created_at
          updated_at
          organization_id
        ].freeze

        class << self
          extend ::Gitlab::Utils::Override

          override :serialize
          def serialize(record)
            new(record.id, record.es_parent).serialize
          end

          override :instantiate
          def instantiate(string)
            _, id, routing = delimit(string)
            new(id, routing)
          end

          override :preload_indexing_data
          def preload_indexing_data(refs)
            ids = refs.map(&:identifier)
            records = model_klass.id_in(ids).preload_indexing_data

            records_by_id = records.index_by(&:id)
            # Group#active? walks the hierarchy per record. Resolve the whole batch in one
            # query instead, or indexing is N+1 in the number of documents.
            active_ids = model_klass.id_in(ids).self_and_ancestors_active.pluck_primary_key.to_set

            refs.each do |ref|
              record = records_by_id[ref.identifier]
              record.elastic_active = active_ids.include?(record.id) if record
              ref.database_record = record
            end

            refs
          end

          def index
            environment_specific_index_name(INDEX_NAME)
          end

          def model_klass
            ::Group
          end
        end

        attr_reader :identifier, :routing

        def initialize(identifier, routing)
          @identifier = identifier.to_i
          @routing = routing
        end

        override :serialize
        def serialize
          self.class.join_delimited([klass, identifier, routing].compact)
        end

        override :as_indexed_json
        def as_indexed_json
          internal_es_fields.tap do |fields|
            add_direct_fields(fields)
            add_computed_fields(fields)
          end
        end

        override :index_name
        def index_name
          self.class.index
        end

        private

        def add_direct_fields(fields)
          DIRECT_FIELDS.each do |name|
            set_field(fields, name) { safely_read_attribute_for_elasticsearch(database_record, name) }
          end
        end

        # preload_indexing_data resolves this for a whole batch; fall back for a single
        # reference serialized outside that path.
        def active_state
          state = database_record.elastic_active
          return state unless state.nil?

          database_record.active?
        end

        def add_computed_fields(fields)
          fields.merge!(
            full_name: database_record.full_name,
            full_path: database_record.full_path,
            traversal_ids: database_record.elastic_namespace_ancestry,
            archived: database_record.archived?
          )

          # Ancestor-aware, unlike archived: GroupsFinder filters active on
          # self_and_ancestors_active, so an own-flag would diverge for subgroups.
          # The index is dynamic: 'strict', so this must wait for the mapping migration.
          set_field(fields, 'active') { active_state }

          set_field(fields, 'organization_traversal_ids') do
            ::Search.organization_traversal_ids(
              database_record.organization_id, database_record.elastic_namespace_ancestry
            )
          end
        end
      end
    end
  end
end
