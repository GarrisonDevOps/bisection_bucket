# frozen_string_literal: true

module Types
  module Ci
    # rubocop:disable Graphql/AuthorizeTypes -- This object is already authorized by the resolver that uses it. This type is mapped onto a simple hash, and therefore will not have a policy class for it.
    class RunnerGkeProvisioningStepType < BaseObject
      graphql_name 'CiRunnerGkeProvisioningStep'
      description 'Step used to provision the runner to GKE.'

      field :title, GraphQL::Types::String,
        null: true, description: 'Title of the step.'

      field :instructions, GraphQL::Types::String,
        null: true, description: 'Instructions to provision the runner.'

      field :language_identifier, GraphQL::Types::String,
        null: true,
        description: 'Identifier of the language used for the instructions field. ' \
          'This identifier can be any of the identifiers specified in the ' \
          '[list of supported languages and lexers](https://codeberg.org/rouge-ruby/rouge/src/branch/main/docs/Languages.md).'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
