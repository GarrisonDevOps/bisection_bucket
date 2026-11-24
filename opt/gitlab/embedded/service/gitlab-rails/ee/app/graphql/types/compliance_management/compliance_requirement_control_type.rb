# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- We just need to list down all types of requirement controls so no auth required
module Types
  module ComplianceManagement
    class ComplianceRequirementControlType < ::Types::BaseObject
      graphql_name 'ComplianceRequirementControl'
      description 'Lists down all the possible types of requirement controls.'

      field :control_expressions, [::Types::ComplianceManagement::ControlExpressionType], null: false,
        description: 'List of requirement controls.'

      def control_expressions
        path = Rails.root.join('ee/config/compliance_management/requirement_controls.json')
        ::Gitlab::Json.parse(File.read(path)).map do |control|
          ::ComplianceManagement::ControlExpression.new(id: control['id'], name: control['name'], expression: {
            field: control['expression']['field'],
            operator: control['expression']['operator'],
            value: control['expression']['value']
          }
          )
        end
      end
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
