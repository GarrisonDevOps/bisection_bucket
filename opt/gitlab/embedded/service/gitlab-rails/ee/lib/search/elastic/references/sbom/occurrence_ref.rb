# frozen_string_literal: true

module Search
  module Elastic
    module References
      module Sbom
        class OccurrenceRef < Reference
          include Search::Elastic::Concerns::DatabaseReference
          include Search::Elastic::Concerns::SchemaVersionedReference
          include ::Gitlab::Utils::StrongMemoize

          DOC_TYPE = 'sbom_occurrence_ref'
          INDEX_NAME = 'sbom_occurrence_refs'

          # Fields that need a migration to be finished. Use #set_field to conditionally set a field value
          # depending on if the migration has completed.
          FIELDS_WITH_MIGRATIONS = {
            'policy_violations' => :add_policy_violations_to_sbom_occurrence_refs
          }.freeze

          # Maps schema versions to their corresponding migration names.
          # Set migration to nil for baseline versions that don't require migration completion.
          # The schema_version method dynamically selects the highest version whose migration
          # has completed.
          SCHEMA_VERSIONS = {
            26_02 => FIELDS_WITH_MIGRATIONS['policy_violations'],
            26_01 => nil
          }.freeze
          SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max.freeze

          DEFAULT_SOURCE_FIELDS = %w[sbom_occurrence_id].freeze

          # Fields read directly from the sbom_occurrence_refs row.
          DIRECT_FIELDS = %w[
            project_id
            sbom_occurrence_id
            security_project_tracked_context_id
            pipeline_id
            commit_sha
          ].freeze

          # Fields read directly from the associated sbom_occurrences row.
          OCCURRENCE_FIELDS = %w[
            component_name
            component_id
            component_version_id
            source_id
            package_manager
            input_file_path
            vulnerability_count
            archived
            uuid
            created_at
            updated_at
          ].freeze

          # Fields assigned per batch by `.preload_indexing_data` rather than read off a column.
          PRELOADED_FIELDS = %w[
            policy_violations
            malware
          ].freeze

          # Enum fields indexed as their integer value via `#{field}_before_type_cast`.
          ENUM_TYPECAST_FIELDS = {
            'highest_severity' => :occurrence,
            'reachability' => :reachability_record,
            'source_type' => :source,
            'purl_type' => :component,
            'component_type' => :component
          }.freeze

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

              ::Search::Elastic::Preloaders::SbomOccurrenceRef::EnhancedProxy
                .new(refs, records)
                .preload_and_enhance!

              refs
            end

            def index
              environment_specific_index_name(INDEX_NAME)
            end

            def model_klass
              ::Sbom::OccurrenceRef
            end
          end

          attr_reader :identifier, :routing

          def initialize(identifier, routing)
            @identifier = identifier.to_i
            @routing = routing
          end

          override :klass
          def klass
            'Sbom::OccurrenceRef'
          end

          override :serialize
          def serialize
            self.class.join_delimited([klass, identifier, routing].compact)
          end

          override :as_indexed_json
          def as_indexed_json
            validate_record!(database_record)

            internal_es_fields.tap do |fields|
              add_direct_fields(fields)
              add_occurrence_fields(fields)
              add_enum_typecast_fields(fields)
              add_fields_from_associations(fields)
              add_preloaded_fields(fields)
            end
          end

          override :index_name
          def index_name
            self.class.index
          end

          private

          # sbom_occurrence_refs lives in the sec database and its project is cleaned up by a loose
          # foreign key, so the row outlives the project it points at. Indexing one would raise and
          # unwind the whole bulk batch before it is cleared from the queue.
          def validate_record!(record)
            return unless record.project.nil?

            raise ::Elastic::Latest::DocumentShouldBeDeletedFromIndexError.new(model_klass.name, record.id)
          end

          def occurrence
            database_record.occurrence
          end
          strong_memoize_attr :occurrence

          def component
            occurrence.component
          end
          strong_memoize_attr :component

          # A ref whose reachability ingestion has not written yet falls back to the occurrence.
          def reachability_record
            database_record.reachability.nil? ? occurrence : database_record
          end

          def component_version
            occurrence.component_version
          end
          strong_memoize_attr :component_version

          def source
            occurrence.source
          end
          strong_memoize_attr :source

          def add_direct_fields(fields)
            DIRECT_FIELDS.each do |name|
              set_field(fields, name) { database_record.read_attribute(name) }
            end
          end

          def add_occurrence_fields(fields)
            OCCURRENCE_FIELDS.each do |name|
              set_field(fields, name) { occurrence.read_attribute(name) }
            end
          end

          def add_enum_typecast_fields(fields)
            ENUM_TYPECAST_FIELDS.each do |name, target|
              set_field(fields, name) do
                __send__(target)&.public_send(:"#{name}_before_type_cast") # rubocop:disable GitlabSecurity/PublicSend -- target/field names are from a frozen constant
              end
            end
          end

          def add_fields_from_associations(fields)
            primary, secondary = occurrence_licenses

            fields.merge!({
              is_default: database_record.tracked_context.is_default,
              traversal_ids: database_record.project.namespace.elastic_namespace_ancestry,
              component_version: component_version&.version,
              primary_license_spdx_identifier: primary&.fetch(:spdx_identifier, nil),
              primary_license_name: primary&.fetch(:name, nil),
              secondary_license_spdx_identifier: secondary&.fetch(:spdx_identifier, nil),
              secondary_license_name: secondary&.fetch(:name, nil),
              source_package_name: component_version&.source_package_name
            })
          end

          def add_preloaded_fields(fields)
            PRELOADED_FIELDS.each do |name|
              set_field(fields, name) { fetch_record_attribute(database_record, name) }
            end
          end

          # A record that skipped preloading is not a proxy and answers to neither field. Both are
          # scalar mappings, so the fallback has to be a value a term filter can match.
          def fetch_record_attribute(record, attribute)
            return record.public_send(attribute) if record.respond_to?(attribute) # rubocop:disable GitlabSecurity/PublicSend -- frozen constant

            ::Search::Elastic::Preloaders::SbomOccurrenceRef::EnhancedProxy.default_value_for(attribute, record)
          end

          def occurrence_licenses
            Array(occurrence.licenses).first(2).map do |license|
              {
                spdx_identifier: license['spdx_identifier'],
                name: license['name']
              }
            end
          end
        end
      end
    end
  end
end
