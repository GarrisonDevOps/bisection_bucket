# frozen_string_literal: true

module Search
  module Elastic
    module References
      class User < Reference
        include Search::Elastic::Concerns::DatabaseReference
        include Search::Elastic::Concerns::SchemaVersionedReference
        include Gitlab::Utils::StrongMemoize

        # Fields that need a migration to be finished before they can be written.
        # `organization_id` is the user's home organization, not a group membership;
        # group membership is already covered by `namespace_ancestry_ids`.
        FIELDS_WITH_MIGRATIONS = {
          'organization_id' => :add_organization_fields_to_users
        }.freeze

        # Maps schema versions to their corresponding migration names.
        # Set migration to nil for baseline versions that don't require migration completion.
        SCHEMA_VERSIONS = {
          26_02 => FIELDS_WITH_MIGRATIONS['organization_id'],
          26_01 => nil
        }.freeze
        SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max.freeze

        DEFAULT_INDEX_ATTRIBUTES = %i[
          id
          username
          email
          public_email
          name
          created_at
          updated_at
          admin
          state
          timezone
          external
        ].freeze

        DOC_TYPE = 'user'

        override :serialize
        def self.serialize(record)
          new(record.id).serialize
        end

        override :instantiate
        def self.instantiate(string)
          _, id = delimit(string)

          new(id)
        end

        override :preload_indexing_data
        def self.preload_indexing_data(refs)
          ids = refs.map(&:database_id)

          records = ::User.id_in(ids).includes(:status, :user_preference, :user_detail, # rubocop: disable CodeReuse/ActiveRecord -- preload needs AR .includes
            members: { source: :namespace })
          records_by_id = records.index_by(&:id)

          refs.each do |ref|
            ref.database_record = records_by_id[ref.database_id]
          end

          refs
        end

        def self.index
          environment_specific_index_name('users')
        end

        def self.model_klass
          ::User
        end

        override :for_indexing
        def self.for_indexing(id, _es_parent)
          new(id)
        end

        attr_reader :identifier, :database_id

        def initialize(id)
          @database_id = id.to_i
          @identifier = "user_#{@database_id}"
        end

        override :serialize
        def serialize
          self.class.join_delimited([klass, database_id].compact)
        end

        override :as_indexed_json
        def as_indexed_json
          record = database_record
          return {} unless record

          data = {}

          DEFAULT_INDEX_ATTRIBUTES.each do |attribute|
            data[attribute.to_s] = safely_read_attribute_for_elasticsearch(record, attribute)
          end

          data['organization'] = safely_read_attribute_for_elasticsearch(record, :company)
          data['in_forbidden_state'] = in_forbidden_state?(record)
          data['status'] = record.status&.message
          data['status_emoji'] = record.status&.emoji
          data['busy'] = record.status&.busy? || false
          data['namespace_ancestry_ids'] = record.search_membership_ancestry
          data['schema_version'] = fetch_schema_version
          data['type'] = DOC_TYPE

          set_field(data, 'organization_id') { record.organization_id }

          data
        end

        override :database_record
        def database_record
          model_klass.find_by_id(database_id)
        end
        strong_memoize_attr :database_record

        override :index_name
        def index_name
          self.class.index
        end

        private

        def in_forbidden_state?(user)
          ::User::FORBIDDEN_SEARCH_STATES.any?(user.state)
        end
      end
    end
  end
end
