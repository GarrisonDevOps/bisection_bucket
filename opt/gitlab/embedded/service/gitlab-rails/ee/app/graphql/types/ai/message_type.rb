# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- its resolver and subscription scope messages to the current user
    class MessageType < Types::BaseObject
      graphql_name 'AiMessage'
      description "AI features communication message"

      def self.authorization_scopes
        [:api, :read_api, :ai_features]
      end

      field :id,
        GraphQL::Types::ID,
        scopes: [:api, :read_api, :ai_features],
        description: 'UUID of the message.'

      field :request_id, GraphQL::Types::String,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'UUID of the original request. Shared between chat prompt and response.'

      field :content, GraphQL::Types::String,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Raw response content.'

      field :content_html, GraphQL::Types::String,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Response content as HTML.'

      field :role,
        Types::Ai::MessageRoleEnum,
        null: false,
        scopes: [:api, :read_api, :ai_features],
        description: 'Message owner role.'

      field :timestamp,
        Types::TimeType,
        null: false,
        scopes: [:api, :read_api, :ai_features],
        description: 'Message creation timestamp.'

      field :chunk_id,
        GraphQL::Types::Int,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Incremental ID for a chunk from a streamed message. Null when it is not a streamed message.'

      field :errors, [GraphQL::Types::String],
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Message errors.'

      field :type, Types::Ai::MessageTypeEnum,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Message type.'

      field :extras,
        Types::Ai::MessageExtrasType,
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Extra message metadata.'

      field :thread_id,
        ::Types::GlobalIDType[::Ai::Conversation::Thread],
        null: true,
        scopes: [:api, :read_api, :ai_features],
        description: 'Global ID of the existing thread for the Chat conversation.'

      # TODO: phase out xid in favor of actual ActiveRecord id
      def id
        case object
        when ::Ai::Conversation::Message
          object.message_xid
        else # Hash-like
          object['id']
        end
      end

      def thread_id
        case object
        when ::Ai::Conversation::Message
          object.thread&.id
        else # Hash-like
          object['thread']&.id
        end
      end

      def errors
        case object
        when ::Ai::Conversation::Message
          object.error_details
        else # Hash-like
          object['errors']
        end
      end

      def content_html
        return if object['chunk_id']
        return if errors.present?

        banzai_options = {
          current_user: current_user,
          only_path: false,
          pipeline: :full,
          allow_comments: false,
          skip_project_check: true
        }

        Banzai.render_and_post_process(object['content'], banzai_options)
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
