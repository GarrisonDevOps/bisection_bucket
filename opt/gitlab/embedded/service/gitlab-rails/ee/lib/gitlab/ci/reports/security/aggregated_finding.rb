# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module Security
        class AggregatedFinding
          attr_reader :findings

          def initialize(pipeline, findings)
            @pipeline = pipeline
            @findings = findings
          end

          def created_at
            @pipeline&.created_at
          end
        end
      end
    end
  end
end
