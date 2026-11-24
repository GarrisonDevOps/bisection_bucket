# frozen_string_literal: true

module Search
  module Elastic
    module Preloaders
      module SbomOccurrenceRef
        class PolicyViolations < Base
          def perform_preload
            uuid_by_id = records.to_h { |record| [record.id, record.occurrence.uuid] }
            uuids = uuid_by_id.values.uniq
            return {} if uuids.empty?

            dismissed = ::Security::PolicyDismissal.dismissed_license_occurrence_uuids(uuids).to_set

            uuid_by_id.transform_values do |uuid|
              if dismissed.include?(uuid)
                ::Security::PolicyViolations::DISMISSED_IN_MR
              else
                ::Security::PolicyViolations::NOT_APPLICABLE
              end
            end
          end
        end
      end
    end
  end
end
