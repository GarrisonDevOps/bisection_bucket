# frozen_string_literal: true

module RemoteDevelopment
  module Enums
    module WorkspaceVariable
      extend ActiveSupport::Concern

      WORKSPACE_VARIABLE_TYPES = {
        environment: 0,
        file: 1
      }.freeze

      ENVIRONMENT_TYPE = WORKSPACE_VARIABLE_TYPES[:environment].freeze
      FILE_TYPE = WORKSPACE_VARIABLE_TYPES[:file].freeze

      # TODO: Add support for file variables in GraphQL - https://gitlab.com/gitlab-org/gitlab/-/issues/465979
      WORKSPACE_VARIABLE_TYPES_FOR_GRAPHQL =
        WORKSPACE_VARIABLE_TYPES
          .except(:file)
          .transform_keys { |key| key.to_s.upcase }
          .freeze
    end
  end
end
