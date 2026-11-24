# frozen_string_literal: true

module API
  class Chat < ::API::Base
    include APIGuard

    feature_category :chat_engine

    allow_access_with_scope :ai_features

    helpers ::API::Helpers::AiUsersPerIpLimitHelpers

    AVAILABLE_RESOURCES = %w[issue epic group project merge_request commit build work_item].freeze
    RESOURCE_TYPE_MAPPING = { 'build' => 'Ci::Build' }.freeze

    before do
      authenticate!

      Feature.enabled?(:duo_evaluation_ready, :instance) # no-op
      not_found! unless Feature.enabled?(:access_rest_chat, current_user)
    end

    helpers do
      def user_allowed?(resource)
        Ability.allowed?(current_user, "read_#{resource.to_ability_name}", resource) &&
          Llm::ChatService.new(current_user, resource).valid?
      end

      def find_resource(parameters)
        return current_user unless parameters[:resource_type] && parameters[:resource_id]
        return commit_object(parameters) if parameters[:resource_type] == 'commit'

        resource_type = RESOURCE_TYPE_MAPPING[parameters[:resource_type]] || parameters[:resource_type]
        object = resource_type.camelize.safe_constantize
        object.find(parameters[:resource_id])
      end

      def commit_object(parameters)
        project = ::Project.find(parameters[:project_id])
        project.commit_by(oid: parameters[:resource_id])
      end
    end

    namespace 'chat' do
      resources :completions do
        desc 'Generate a Chat response' do
          detail 'Generates a response for a GitLab Duo Chat question.'
          tags ['gitlab_duo']
        end
        params do
          requires :content, type: String, limit: 1000, desc: 'Question sent to Chat.'
          optional :resource_type, type: String, limit: 100, values: AVAILABLE_RESOURCES, desc: 'Type of resource ' \
                                                                                            'sent with the chat ' \
                                                                                            'question.'
          optional :resource_id, types: [String, Integer],
            desc: 'ID of the resource. Can be a numeric ID or a commit SHA.'
          optional :referer_url, type: String, limit: 1000, desc: 'Referer URL.'
          optional :client_subscription_id, type: String, limit: 500, desc: 'Client subscription ID.'
          optional :with_clean_history, type: Boolean,
            desc: 'If `true`, resets history before and after the request.'
          optional :project_id, type: Integer,
            desc: 'ID of the project. Required when `resource_type` is `commit`.'
          optional :current_file, type: Hash, desc: 'Object that contains information about the current file.' do
            optional :file_name, type: String, limit: 1000, desc: 'Name of the current file.'
            optional :content_above_cursor, type: String,
              limit: ::API::CodeSuggestions::MAX_CONTENT_SIZE, desc: 'Content above cursor.'
            optional :content_below_cursor, type: String,
              limit: ::API::CodeSuggestions::MAX_CONTENT_SIZE, desc: 'Content below cursor.'
            optional :selected_text, type: String,
              limit: ::API::CodeSuggestions::MAX_CONTENT_SIZE,
              desc: 'Content currently selected by the user.'
          end
          optional :additional_context, type: Array, allow_blank: true,
            desc: 'Additional context to pass to the chat request. See [Context ' \
              'attributes](https://docs.gitlab.com/api/chat/#context-attributes) for the parameters this ' \
              'attribute accepts.' do
            requires :category, type: String,
              values: ::Ai::AdditionalContext::DUO_CHAT_CONTEXT_CATEGORIES.values,
              desc: 'Category of the additional context.'
            requires :id, type: String,
              limit: ::Ai::AdditionalContext::MAX_CONTEXT_TYPE_SIZE, allow_blank: false,
              desc: 'ID of the additional context.'
            requires :content, type: String,
              limit: ::Ai::AdditionalContext::MAX_BODY_SIZE, allow_blank: false,
              desc: 'Content of the additional context.'
            optional :metadata, type: Hash, allow_blank: true,
              desc: 'Metadata of the additional context.'
          end
        end
        route_setting :authorization, permissions: :create_chat_completion, boundary_type: :user
        post urgency: :low do # internal use only
          check_ai_users_per_ip_limit!

          safe_params = declared_params(include_missing: false)

          if safe_params[:additional_context].present?
            safe_params[:additional_context].map do |context|
              context.tap do |c|
                c["metadata"] ||= {}
              end
            end
          end

          resource = find_resource(safe_params)

          not_found! unless user_allowed?(resource)

          ai_response = ::Gitlab::Duo::Chat::Completions.new(current_user, resource: resource)
                                                        .execute(safe_params: safe_params)

          present ai_response.response_body
        end
      end
    end
  end
end
