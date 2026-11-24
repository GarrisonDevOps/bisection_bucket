# frozen_string_literal: true

module Search
  module Elastic
    module RecordProxy
      # Sbom::OccurrenceRef proxy that answers for the values resolved per indexing batch:
      # policy_violations and malware.
      class SbomOccurrenceRef < Base
        def self.create_with_enhancements(record, enhancements)
          new(record).tap do |proxy|
            proxy.enhance_with_data(enhancements)
          end
        end
      end
    end
  end
end
