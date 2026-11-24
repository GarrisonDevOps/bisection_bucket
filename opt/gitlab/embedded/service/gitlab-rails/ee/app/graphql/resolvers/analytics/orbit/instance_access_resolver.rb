# frozen_string_literal: true

module Resolvers
  module Analytics
    module Orbit
      class InstanceAccessResolver < BaseResolver
        type ::Types::Analytics::Orbit::AccessType, null: true

        def resolve
          :instance if ::Ability.allowed?(current_user, :read_orbit_instance_access, :global)
        end
      end
    end
  end
end
