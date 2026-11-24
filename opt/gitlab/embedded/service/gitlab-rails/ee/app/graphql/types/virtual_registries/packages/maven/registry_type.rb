# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        class RegistryType < ::Types::BaseObject
          graphql_name 'MavenRegistry'
          description 'Represents a Maven virtual registry'

          authorize :read_virtual_registry
          connection_type_class ::Types::CountableConnectionType

          implements Types::VirtualRegistries::RegistryInterface

          alias_method :registry, :object
        end
      end
    end
  end
end
