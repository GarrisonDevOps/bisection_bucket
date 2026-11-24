# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Upstream
          class RuleType < ::Types::BaseObject
            graphql_name 'MavenUpstreamRule'
            description 'Represents a Maven upstream rule.'

            authorize :read_virtual_registry

            implements ::Types::VirtualRegistries::Upstream::RuleInterface
          end
        end
      end
    end
  end
end
