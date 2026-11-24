# frozen_string_literal: true

module ComplianceManagement
  module ComplianceRequirements
    class ExpressionEvaluator
      include Gitlab::Utils::StrongMemoize

      def initialize(control, project, approval_settings = [])
        @control = control
        @project = project
        @approval_settings = approval_settings
      end

      def evaluate
        return if parsed_expression.nil?

        field_value = fetch_field_value
        return field_value if field_value == :not_applicable

        ComparisonOperator.compare(
          field_value,
          parsed_expression[:value],
          parsed_expression[:operator]
        )
      end

      private

      attr_reader :control, :project, :approval_settings

      def parsed_expression
        control.expression_as_hash(symbolize_names: true)
      end
      strong_memoize_attr :parsed_expression

      def fetch_field_value
        ProjectFields.map_field(project,
          parsed_expression[:field],
          { approval_settings: approval_settings })
      end
    end
  end
end
