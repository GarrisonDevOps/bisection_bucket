# frozen_string_literal: true

module EE
  module Types
    module Ci
      module JobInterface
        extend ActiveSupport::Concern

        prepended do
          orphan_types ::Types::Ci::JobMinimalAccessType
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :resolve_type
          def resolve_type(object, context)
            user = context[:current_user]

            return ::Types::Ci::JobType if Ability.allowed?(user, :read_build, object)
            return ::Types::Ci::JobMinimalAccessType if Ability.allowed?(user, :read_build_metadata, object)

            ::Types::Ci::JobType
          end
        end
      end
    end
  end
end
