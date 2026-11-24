# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyDiff
      class FieldDiff
        attr_reader :from, :to

        def initialize(from:, to:)
          @from = from
          @to = to
        end

        def to_h
          {
            from: from,
            to: to
          }
        end
      end
    end
  end
end
