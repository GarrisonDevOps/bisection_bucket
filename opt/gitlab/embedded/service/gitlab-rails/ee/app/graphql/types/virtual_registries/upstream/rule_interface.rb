# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Upstream
      module RuleInterface
        include Types::BaseInterface

        field :id, ::Types::GlobalIDType[::VirtualRegistries::Packages::Maven::Upstream::Rule],
          null: false,
          description: 'Global ID of the rule.'

        field :pattern, GraphQL::Types::String,
          null: false,
          description: 'Pattern for the rule.'

        field :pattern_type, ::Types::VirtualRegistries::Packages::Maven::Upstream::Rules::PatternTypeEnum,
          null: false,
          description: 'Type of pattern (WILDCARD or REGEX).'

        field :target_coordinate,
          ::Types::VirtualRegistries::Packages::Maven::Upstream::Rules::TargetCoordinateEnum,
          null: false,
          description: 'Target coordinate for the rule.'

        field :created_at, ::Types::TimeType,
          null: false,
          description: 'When the rule was created.'

        def pattern_type
          object.pattern_type.upcase
        end

        def target_coordinate
          object.target_coordinate.upcase
        end
      end
    end
  end
end
