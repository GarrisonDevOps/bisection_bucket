# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Upstream
          module Rules
            class PatternTypeEnum < ::Types::BaseEnum
              graphql_name 'MavenUpstreamPatternType'
              description 'Pattern type for Maven upstream rules.'

              value 'WILDCARD', description: 'Wildcard pattern type.'
              value 'REGEX', description: 'Regular expression pattern type.'
            end
          end
        end
      end
    end
  end
end
