# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      class DocsClient
        include ::Gitlab::Llm::Concerns::ExponentialBackoff
        include ::Gitlab::Llm::Concerns::EventTracking
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::Llm::Concerns::Logger

        DEFAULT_TYPE = 'search-docs'
        DEFAULT_SOURCE = 'GitLab EE'

        def initialize(user, tracking_context: {}, namespace_id: nil, project_id: nil, governing_namespace_id: nil)
          @user = user
          @tracking_context = tracking_context
          @namespace_id = namespace_id
          @project_id = project_id
          @governing_namespace_id = governing_namespace_id
        end

        def search(query:, **options)
          perform_search_request(query: query, options: options)
        end

        private

        attr_reader :user, :tracking_context, :namespace_id, :project_id, :governing_namespace_id

        def perform_search_request(query:, options:)
          log_info(message: "Searching docs from AI Gateway",
            event_name: 'performing_request',
            ai_component: 'duo_chat',
            options: options)
          timeout = options.delete(:timeout) || Gitlab::AiGateway.timeout

          response = Gitlab::HTTP.post(
            "#{base_url}/v1/search/gitlab-docs",
            headers: Gitlab::AiGateway.headers(
              user: user,
              unit_primitive_name: :duo_classic_chat,
              ai_feature_name: :chat,
              organization_id: ::Ai::UserAuthorizer.for(user).governing_namespace&.organization_id,
              namespace_id: namespace_id,
              project_id: project_id,
              governing_namespace_id: governing_namespace_id || ::Ai::UserAuthorizer.for(user).governing_namespace&.id
            ),
            body: request_body(query: query).to_json,
            timeout: timeout,
            allow_local_requests: true
          )

          log_conditional_info(user,
            message: "Searched docs content from AI Gateway",
            event_name: 'response_received',
            ai_component: 'duo_chat',
            response_from_llm: response)

          response
        end

        def base_url
          feature_setting&.base_url || Gitlab::AiGateway.url
        end

        def feature_setting
          ::Ai::FeatureSetting.find_by_feature(:duo_chat)
        end

        def request_body(query:)
          {
            type: DEFAULT_TYPE,
            metadata: {
              source: DEFAULT_SOURCE,
              version: Gitlab.version_info.to_s
            },
            payload: {
              query: query
            }
          }
        end
      end
    end
  end
end
