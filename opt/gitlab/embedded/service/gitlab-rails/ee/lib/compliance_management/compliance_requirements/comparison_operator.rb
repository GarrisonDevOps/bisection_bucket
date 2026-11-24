# frozen_string_literal: true

module ComplianceManagement
  module ComplianceRequirements
    module ComparisonOperator
      def self.compare(actual, expected, operator)
        case operator
        when '=' then actual == expected
        when '!=' then actual != expected
        when '>' then actual > expected
        when '<' then actual < expected
        when '>=' then actual >= expected
        when '<=' then actual <= expected
        else
          raise ArgumentError, "Unknown operator: #{operator}"
        end
      end
    end
  end
end
