# frozen_string_literal: true

module EE
  module Types
    module Namespaces
      module GroupInterface
        extend ActiveSupport::Concern

        prepended do
          orphan_types ::Types::Namespaces::GroupMinimalAccessType
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :resolve_type
          def resolve_type(object, context)
            user = context[:current_user]

            return ::Types::GroupType if Ability.allowed?(user, :read_group, object)
            return ::Types::Namespaces::GroupMinimalAccessType if Ability.allowed?(user, :read_group_metadata, object)

            ::Types::GroupType
          end
        end
      end
    end
  end
end
