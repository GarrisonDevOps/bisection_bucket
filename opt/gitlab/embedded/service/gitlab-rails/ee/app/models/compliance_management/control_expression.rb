# frozen_string_literal: true

module ComplianceManagement
  class ControlExpression
    include GlobalID::Identification
    extend Gitlab::Utils::StrongMemoize

    attr_reader :id, :name, :expression

    REQUIREMENT_CONTROLS_JSON_PATH = Rails.root.join('ee/config/compliance_management/requirement_controls.json')

    def self.find(id)
      control = predefined_controls.find { |control| control[:id] == id }

      return unless control

      ComplianceManagement::ControlExpression.new(
        id: control[:id],
        name: control[:name],
        expression: control[:expression]
      )
    end

    def self.predefined_controls
      strong_memoize(:predefined_controls) do
        ::Gitlab::Json.safe_parse(File.read(REQUIREMENT_CONTROLS_JSON_PATH), symbolize_names: true)
      end
    end

    def initialize(id:, name:, expression:)
      @id = id
      @name = name
      @expression = expression
    end

    def to_global_id
      id.to_s
    end

    def matches_expression?(control_expression)
      expression == control_expression
    end
  end
end
