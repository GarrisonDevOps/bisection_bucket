# frozen_string_literal: true

module Search
  module Elastic
    module References
      module Vulnerabilities
        class Read < Reference
          include Search::Elastic::Concerns::DatabaseReference
          include Search::Elastic::Concerns::SchemaVersionedReference
          include ::Gitlab::Utils::StrongMemoize

          DOC_TYPE = 'vulnerability'
          INDEX_NAME = 'vulnerability_reads'

          FIELDS_WITH_MIGRATIONS = {
            'is_default' => :add_is_default_to_vulnerability_reads,
            'organization_id' => :add_organization_id_to_vulnerability_reads,
            'remediated_at' => :add_remediated_at_to_vulnerability_reads,
            'due_date' => :add_due_date_to_vulnerability_reads,
            'ascp_security_context' => :add_ascp_security_context_to_vulnerability_reads
          }.freeze

          # Maps schema versions to their corresponding migration names.
          # Set migration to nil for baseline versions that don't require migration completion.
          # The schema_version method dynamically selects the highest version whose migration
          # has completed.
          SCHEMA_VERSIONS = {
            26_07 => FIELDS_WITH_MIGRATIONS['ascp_security_context'],
            26_06 => FIELDS_WITH_MIGRATIONS['due_date'],
            26_05 => FIELDS_WITH_MIGRATIONS['remediated_at'],
            26_04 => FIELDS_WITH_MIGRATIONS['organization_id'],
            26_03 => nil,
            26_02 => FIELDS_WITH_MIGRATIONS['is_default'],
            26_01 => nil
          }.freeze
          SCHEMA_VERSION = SCHEMA_VERSIONS.keys.max.freeze

          DIRECT_FIELDS = %w[
            vulnerability_id
            project_id
            scanner_id
            uuid
            location_image
            cluster_agent_id
            casted_cluster_agent_id
            has_issues
            resolved_on_default_branch
            has_merge_request
            has_remediations
            archived
            has_vulnerability_resolution
            auto_resolved
            identifier_names
            security_project_tracked_context_id
            vulnerability_occurrence_id
          ].freeze

          DIRECT_TYPECAST_FIELDS = %w[report_type severity state dismissal_reason].freeze

          DEFAULT_SOURCE_FIELDS = %w[vulnerability_occurrence_id].freeze

          PRELOADED_FIELDS = %w[
            risk_score
            reachability
            token_status
            policy_violations
            false_positive
            undetected_since
            policy_auto_dismissed
            is_default
            latest_flag
            due_date
            ascp_security_context
          ].freeze

          class << self
            extend ::Gitlab::Utils::Override

            override :serialize
            def serialize(record)
              new(record[:id], record.es_parent).serialize
            end

            override :instantiate
            def instantiate(string)
              _, id, routing = delimit(string)
              new(id, routing)
            end

            override :preload_indexing_data
            def preload_indexing_data(refs)
              # TODO: Remove the backfill check once BBM is finalized - https://gitlab.com/gitlab-org/gitlab/-/work_items/594422
              return refs unless backfill_occurrence_id_completed?

              ids = refs.map(&:identifier)
              records = model_klass.preload_indexing_data.id_in(ids)
              ::Search::Elastic::Preloaders::VulnerabilityRead::EnhancedProxy.new(refs, records).preload_and_enhance!

              refs
            end

            def index
              environment_specific_index_name(INDEX_NAME)
            end

            def model_klass
              ::Vulnerabilities::Read
            end

            private

            def backfill_occurrence_id_completed?
              migration = Gitlab::Database::SharedModel.using_connection(SecApplicationRecord.connection) do
                Gitlab::Database::BackgroundMigration::BatchedMigration.find_for_configuration(
                  :gitlab_sec,
                  'BackfillOccurrenceIdToVulnerabilityReads',
                  :vulnerability_reads,
                  :id,
                  []
                )
              end
              return false unless migration

              migration.finished? || migration.finalized?
            end
          end

          attr_reader :identifier, :routing

          def initialize(identifier, routing)
            @identifier = identifier.to_i
            @routing = routing
          end

          override :klass
          def klass
            'Vulnerabilities::Read'
          end

          override :serialize
          def serialize
            self.class.join_delimited([klass, identifier, routing].compact)
          end

          override :as_indexed_json
          def as_indexed_json
            internal_es_fields.tap do |fields|
              add_direct_fields(fields)
              add_direct_typecast_fields(fields)
              add_preloaded_fields(fields)
              add_fields_from_associations(fields)
            end
          end

          override :index_name
          def index_name
            self.class.index
          end

          private

          def add_direct_fields(fields)
            DIRECT_FIELDS.each do |name|
              set_field(fields, name) { database_record.read_attribute(name) }
            end
          end

          def add_direct_typecast_fields(fields)
            DIRECT_TYPECAST_FIELDS.each do |name|
              set_field(fields, name) { database_record.method(:"#{name}_before_type_cast").call }
            end
          end

          def add_preloaded_fields(fields)
            PRELOADED_FIELDS.each do |name|
              set_field(fields, name) { fetch_record_attribute(database_record, name.to_sym) }
            end
          end

          def add_fields_from_associations(fields)
            # TODO: Fetch resolved_at, dismissed_at from
            # vulnerability_state_transitions table
            # https://gitlab.com/gitlab-org/gitlab/-/work_items/594422
            fields.merge!({
              scanner_external_id: database_record.scanner&.external_id,
              created_at: database_record.vulnerability_occurrence&.created_at,
              updated_at: database_record.vulnerability_occurrence&.updated_at,
              detected_at: database_record.vulnerability_occurrence&.detected_at,
              resolved_at: database_record.vulnerability.resolved_at,
              dismissed_at: database_record.vulnerability.dismissed_at,
              traversal_ids: database_record.project.namespace.elastic_namespace_ancestry
            })

            set_field(fields, 'organization_id') { database_record.project.namespace.organization_id }
            set_field(fields, 'remediated_at') { earliest_remediation_timestamp(fields) }
          end

          # undetected_since is `[]`, not nil, when the record skipped preloading
          def earliest_remediation_timestamp(fields)
            fields.values_at('resolved_at', 'undetected_since').grep(Time).min
          end

          def fetch_record_attribute(record, attribute)
            return record.method(attribute).call if record.respond_to?(attribute)

            []
          end
        end
      end
    end
  end
end
