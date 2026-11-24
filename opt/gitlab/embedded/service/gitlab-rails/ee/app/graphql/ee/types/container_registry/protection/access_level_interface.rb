# frozen_string_literal: true

module EE
  module Types
    module ContainerRegistry
      module Protection
        module AccessLevelInterface
          extend ActiveSupport::Concern

          prepended do
            delete_field, push_field = fields.values_at('minimumAccessLevelForDelete', 'minimumAccessLevelForPush')
            [delete_field, push_field].each { |field| field.instance_variable_set(:@return_type_null, true) }
            delete_field.description = "#{delete_field.description}" \
              'If the value is `nil`, no access level can delete tags. '
            push_field.description = "#{push_field.description}" \
              'If the value is `nil`, no access level can push tags. '

            field :immutable,
              GraphQL::Types::Boolean,
              null: false,
              method: :immutable?,
              description: 'Returns true when tag rule is for tag immutability. Otherwise, false.'
          end
        end
      end
    end
  end
end
