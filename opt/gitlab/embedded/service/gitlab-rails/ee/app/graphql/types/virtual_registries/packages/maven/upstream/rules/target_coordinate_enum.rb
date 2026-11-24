# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Upstream
          module Rules
            class TargetCoordinateEnum < ::Types::BaseEnum
              graphql_name 'MavenUpstreamTargetCoordinate'
              description 'Target coordinate for Maven upstream rules.'

              value 'GROUP_ID', description: 'Group ID coordinate.'
              value 'ARTIFACT_ID', description: 'Artifact ID coordinate.'
              value 'VERSION', description: 'Version coordinate.'
            end
          end
        end
      end
    end
  end
end
