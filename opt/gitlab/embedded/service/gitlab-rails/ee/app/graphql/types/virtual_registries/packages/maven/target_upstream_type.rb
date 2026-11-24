# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        class TargetUpstreamType < ::Types::BaseUnion
          graphql_name 'MavenTargetUpstream'
          description 'Maven remote or local upstream that a registry upstream points to.'

          TypeNotSupportedError = Class.new(StandardError)

          possible_types ::Types::VirtualRegistries::Packages::Maven::UpstreamType,
            ::Types::VirtualRegistries::Packages::Maven::Local::UpstreamType

          def self.resolve_type(object, _context)
            case object
            when ::VirtualRegistries::Packages::Maven::Upstream
              ::Types::VirtualRegistries::Packages::Maven::UpstreamType
            when ::VirtualRegistries::Packages::Maven::Local::Upstream
              ::Types::VirtualRegistries::Packages::Maven::Local::UpstreamType
            else
              raise TypeNotSupportedError, "no Maven target upstream type for #{object.class}"
            end
          end
        end
      end
    end
  end
end
