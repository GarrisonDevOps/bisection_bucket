# frozen_string_literal: true

module Search
  module Elastic
    module Preloaders
      module SbomOccurrenceRef
        # Runs every preloader once for the batch and hands each reference a proxy that answers
        # for the fields which are not columns of sbom_occurrence_refs or sbom_occurrences.
        class EnhancedProxy
          PROXIES = {
            policy_violations: {
              preloader: PolicyViolations,
              default_value: ::Security::PolicyViolations::NOT_APPLICABLE
            },
            malware: {
              preloader: Malware,
              default_value: ->(record) { record.occurrence.malware_status }
            }
          }.with_indifferent_access.freeze

          class << self
            def default_value_for(field, record)
              resolve_default(PROXIES.dig(field, :default_value), record)
            end

            def resolve_default(default, record)
              default.respond_to?(:call) ? default.call(record) : default
            end
          end

          def initialize(refs, records)
            @refs = refs
            @records = Array(records)
            @records_by_id = @records.index_by(&:id)
          end

          def preload_and_enhance!
            preload_all_data
            create_and_assign_proxies
          end

          private

          attr_reader :refs, :records, :records_by_id

          def preload_all_data
            @data_with_default = PROXIES.transform_values do |config|
              config.slice(:default_value).merge(data: config[:preloader].new(records).preload)
            end
          end

          # Assigning nil for a missing row is what lets #operation resolve to :delete without a
          # further find_by_id, so every ref is assigned rather than only the ones with a record.
          def create_and_assign_proxies
            refs.each do |ref|
              record = records_by_id[ref.identifier]

              ref.database_record = record && create_enhanced_proxy(record)
            end
          end

          def create_enhanced_proxy(record)
            ::Search::Elastic::RecordProxy::SbomOccurrenceRef.create_with_enhancements(record, enhancements(record))
          end

          def enhancements(record)
            @data_with_default.transform_values { |data_with_default| value_for(data_with_default, record) }
          end

          def value_for(data_with_default, record)
            value = data_with_default.dig(:data, record.id)
            return value unless value.nil?

            self.class.resolve_default(data_with_default[:default_value], record)
          end
        end
      end
    end
  end
end
