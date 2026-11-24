# frozen_string_literal: true

module Resolvers
  module VirtualRegistries
    module Cleanup
      class PolicyResolver < BaseResolver
        type ::Types::VirtualRegistries::Cleanup::PolicyType, null: true

        alias_method :group, :object

        def resolve(**_args)
          return unless virtual_registry_available?

          ::VirtualRegistries::Cleanup::Policy.find_by_group_id(group.id)
        end

        private

        def authorized?(**_args)
          ::VirtualRegistries.user_has_access?(group, current_user, :read_virtual_registry_cleanup_policy)
        end

        def virtual_registry_available?
          ::VirtualRegistries::Packages::Maven.feature_enabled?(group) ||
            ::VirtualRegistries::Container.feature_enabled?(group)
        end
      end
    end
  end
end
