# frozen_string_literal: true

# noinspection RubyClassModuleNamingConvention - See https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/code-inspection/why-are-there-noinspection-comments/
module EE
  module Types
    module CurrentUserType
      extend ActiveSupport::Concern

      prepended do
        field :workspaces,
          description: 'Workspaces owned by the current user.',
          resolver: ::Resolvers::RemoteDevelopment::WorkspacesResolver

        field :duo_chat_available, ::GraphQL::Types::Boolean,
          resolver: ::Resolvers::Ai::UserChatAccessResolver,
          experiment: { milestone: '16.8' },
          description: 'User access to AI chat feature.'

        field :duo_classic_chat_available, ::GraphQL::Types::Boolean,
          resolver: ::Resolvers::Ai::UserClassicChatAccessResolver,
          description: 'User access to GitLab Duo Chat (non-agentic) feature.'

        field :duo_code_suggestions_available, ::GraphQL::Types::Boolean,
          resolver: ::Resolvers::Ai::CodeSuggestionsAccessResolver,
          experiment: { milestone: '16.8' },
          description: 'User access to code suggestions feature.'

        field :duo_chat_available_features, [::GraphQL::Types::String],
          resolver: ::Resolvers::Ai::UserAvailableFeaturesResolver,
          experiment: { milestone: '17.6' },
          description: 'List of available features for AI chat.'

        field :code_suggestions_contexts, [::GraphQL::Types::String],
          resolver: ::Resolvers::Ai::UserCodeSuggestionsContextsResolver,
          experiment: { milestone: '17.9' },
          description: 'List of additional contexts enabled for Code Suggestions.'

        field :credits_usage, ::Types::GitlabSubscriptions::User::CreditsUsageType,
          null: true,
          resolver: ::Resolvers::GitlabSubscriptions::User::CreditsUsageResolver,
          experiment: { milestone: '19.4' },
          description: "GitLab Credits usage for the current user."
      end
    end
  end
end
