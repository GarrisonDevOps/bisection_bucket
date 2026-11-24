# frozen_string_literal: true

module Ai
  module Governance
    # Integer casting turns `false` into 0, which passes the numericality and inclusion validators, so check
    # the raw input. Other non-numeric input fails numericality. Blank strings cast to nil, which the
    # attribute's own nil handling covers.
    #
    # Usage:
    #   validates :ai_agent_governance_enforcement, 'ai/governance/enforcement_mode_input': true
    class EnforcementModeInputValidator < ActiveModel::EachValidator
      def validate_each(record, attribute, _value)
        return unless record.read_attribute_before_type_cast(attribute) == false

        record.errors.add(attribute, :invalid)
      end
    end
  end
end
