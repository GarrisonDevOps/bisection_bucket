# frozen_string_literal: true

module Types
  module Ai
    module DapFactory
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by the resolver that returns it
      class SyncResultType < BaseObject
        graphql_name 'DapFactorySyncResult'
        authorize_granular_token parent_authorizes: :update_ai_flow_trigger
        description 'Outcome of the last Sync of a DAP Software Factory configuration.'

        field :status, SyncStatusEnum,
          null: false,
          description: 'Outcome of the Sync.'

        field :commit_sha, GraphQL::Types::String,
          null: true,
          description: 'Commit of the default branch that was synced.'

        field :synced_at, Types::TimeType,
          null: true,
          description: 'Timestamp of when the Sync ran.'

        field :errors, [ValidationMessageType],
          null: false,
          description: 'Why the Sync did not apply the file, when its status is `INVALID` or `FAILED`.'

        field :adopted_stages, [GraphQL::Types::String],
          null: false,
          description: 'Stages whose existing triggers, with the description that Sync gives the stage, ' \
            'Sync now manages.'

        field :created_stages, [GraphQL::Types::String],
          null: false,
          description: 'Stages whose triggers were created.'

        field :updated_stages, [GraphQL::Types::String],
          null: false,
          description: 'Stages whose triggers were updated.'

        field :deleted_stages, [GraphQL::Types::String],
          null: false,
          description: 'Stages whose triggers were deleted.'

        field :failed_stages, [ValidationMessageType],
          null: false,
          description: 'Stages whose triggers could not be applied.'

        def errors
          object.errors.map { |error| message(error) }
        end

        def adopted_stages
          object.summary.fetch('adopted', [])
        end

        def created_stages
          object.summary.fetch('created', [])
        end

        def updated_stages
          object.summary.fetch('updated', [])
        end

        def deleted_stages
          object.summary.fetch('deleted', [])
        end

        def failed_stages
          object.summary.fetch('failed', []).map do |failure|
            message('path' => "stages.#{failure['stage']}", 'code' => 'sync_failed', 'message' => failure['message'])
          end
        end

        private

        def message(attributes)
          ::Gitlab::Ai::DapFactory::Validator::Message.new(
            path: attributes['path'], code: attributes['code'], message: attributes['message'])
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
