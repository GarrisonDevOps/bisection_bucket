# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyDiff
      class RuleDiff
        attr_reader :from, :to
        attr_accessor :id

        def initialize(id:, from:, to:)
          @id = id
          @from = from
          @to = to
        end

        def to_h
          {
            id: id,
            from: from.is_a?(Security::PolicyRule) ? from.typed_content : from&.to_h,
            to: to.is_a?(Security::PolicyRule) ? to.typed_content : to&.to_h
          }
        end
      end
    end
  end
end
