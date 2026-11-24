# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module Widgets
        module DevelopmentType
          extend ActiveSupport::Concern
          include ::Gitlab::Utils::StrongMemoize

          prepended do
            field :feature_flags, ::Types::FeatureFlagType.connection_type, null: true,
              description: 'Feature flags associated with the work item.',
              complexity: 10
          end

          def feature_flags
            if object.feature_flags.loaded?
              object.feature_flags
            else
              object.feature_flags.preload_project
            end
          end
        end
      end
    end
  end
end
