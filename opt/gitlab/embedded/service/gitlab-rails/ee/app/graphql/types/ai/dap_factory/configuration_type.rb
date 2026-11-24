# frozen_string_literal: true

module Types
  module Ai
    module DapFactory
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by the resolver that returns it
      class ConfigurationType < BaseObject
        graphql_name 'DapFactoryConfiguration'
        authorize_granular_token permissions: [:read_code, :update_ai_flow_trigger], boundary: :project,
          boundary_type: :project
        description 'The DAP Software Factory configuration file on the default branch of a project.'

        field :path, GraphQL::Types::String,
          null: false,
          description: 'Path of the configuration file in the repository.'

        field :default_branch, GraphQL::Types::String,
          null: true,
          description: 'Default branch the file is read from and synced on.',
          calls_gitaly: true

        field :last_commit_id, GraphQL::Types::String,
          null: true,
          description: 'Last commit that changed the file on the default branch. Pass it back when committing, ' \
            'so a stale save fails. Null when the file does not exist.',
          calls_gitaly: true

        field :exists, GraphQL::Types::Boolean,
          null: false,
          method: :exists?,
          description: 'Whether the file exists on the default branch.',
          calls_gitaly: true

        field :content, GraphQL::Types::String,
          null: true,
          description: 'Content of the file. Null when the file does not exist, or when it is too large ' \
            'to edit safely. Check the errors for the reason.',
          calls_gitaly: true

        field :errors, [ValidationMessageType],
          null: false,
          description: 'Problems that stop Sync from applying the file.',
          calls_gitaly: true

        field :warnings, [ValidationMessageType],
          null: false,
          description: 'Problems that Sync ignores.',
          calls_gitaly: true

        field :auto_review, AutoReviewType,
          null: false,
          description: 'Duo Code Review settings that the Review stage depends on.'

        # rubocop:disable GraphQL/ExtractType -- last_commit_id belongs to the file, not to the Sync result
        field :last_sync, SyncResultType,
          null: true,
          description: 'Outcome of the last Sync. Null when there is no recent Sync result.'
        # rubocop:enable GraphQL/ExtractType

        def auto_review
          ::Ai::DapFactory::AutoReview.new(object.project)
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
