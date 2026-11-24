# frozen_string_literal: true

module Mutations
  module Ai
    class Action < BaseMutation
      graphql_name 'AiAction'

      include ::Gitlab::Llm::Concerns::Logger

      MUTUALLY_EXCLUSIVE_ARGUMENTS_ERROR = 'Only one method argument is required'

      ::Gitlab::Llm::Utils::AiFeaturesCatalogue.external.each_key do |method|
        argument method,
          "Types::Ai::#{method.to_s.camelize}InputType".constantize,
          required: false,
          description: "Input for #{method} AI action."
      end

      argument :client_subscription_id, GraphQL::Types::String,
        required: false,
        description: 'Client generated ID that can be subscribed to, to receive a response for the mutation.'

      argument :platform_origin, GraphQL::Types::String,
        required: false,
        description: 'Specifies the origin platform of the request.'

      argument :project_id, ::Types::GlobalIDType[::Project],
        required: false,
        description: "Global ID of the project the user is acting on."

      argument :root_namespace_id, ::Types::GlobalIDType[::Namespace],
        required: false,
        description: "Global ID of the top-level namespace the user is acting on."

      argument :conversation_type, Types::Ai::Conversations::Threads::ConversationTypeEnum,
        required: false,
        description: 'Conversation type of the thread.'

      argument :thread_id, ::Types::GlobalIDType[::Ai::Conversation::Thread],
        required: false,
        description: 'Global Id of the existing thread to continue the conversation. ' \
          'If it is not specified, a new thread will be created for the specified conversation_type.'

      # We need to re-declare the `errors` because we want to allow ai_features token to work for this
      field :errors, [GraphQL::Types::String],
        null: false,
        scopes: [:api, :ai_features],
        description: 'Errors encountered during the mutation.'

      field :request_id, GraphQL::Types::String,
        scopes: [:api, :ai_features],
        null: true,
        description: 'ID of the request.'

      field :thread_id, ::Types::GlobalIDType[::Ai::Conversation::Thread],
        scopes: [:api, :ai_features],
        null: true,
        description: 'Global Id of the thread.'

      def self.authorization_scopes
        super + [:ai_features]
      end

      def ready?(**args)
        raise Gitlab::Graphql::Errors::ArgumentError, MUTUALLY_EXCLUSIVE_ARGUMENTS_ERROR if methods(args).size != 1

        super
      end

      def graphql_query_details
        return {} unless Feature.enabled?(:expanded_ai_logging, current_user)

        {
          graphql_query_string: context.query.query_string,
          graphql_variables: context.query.variables.to_h
        }
      end

      def resolve(**attributes)
        started_at = Gitlab::Metrics::System.real_time

        verify_rate_limit!

        log_conditional_info(
          current_user,
          message: "Received AiAction mutation GraphQL query",
          event_name: 'ai_action_mutation',
          ai_component: 'abstraction_layer',
          user_id: current_user.id,
          **graphql_query_details
        )

        resource_id, method, options = extract_method_params!(attributes)

        check_feature_flag_enabled!(method)

        resource = find_resource(GlobalID.parse(resource_id), options[:project_id])

        update_option_by_request_headers(method, options)

        handle_chat_arguments(options) if method == :chat

        options[:started_at] = started_at

        response = Llm::ExecuteMethodService.new(current_user, resource, method, options).execute

        if response.error?
          { errors: [response.message] }
        else
          {
            request_id: response[:ai_message].request_id,
            thread_id: response[:ai_message].thread&.to_global_id,
            errors: []
          }
        end
      end

      private

      def update_option_by_request_headers(method, options)
        options[:referer_url] = context[:request].headers["Referer"] if method == :chat
        options[:user_agent] = context[:request].headers["User-Agent"]
        options[:x_gitlab_client_type] = context[:request].headers['X-Gitlab-Client-Type']
        options[:x_gitlab_client_version] = context[:request].headers['X-Gitlab-Client-Version']
        options[:x_gitlab_client_name] = context[:request].headers['X-Gitlab-Client-Name']
        options[:x_gitlab_interface] = context[:request].headers['X-Gitlab-Interface']

        tracking_context = context[:request].headers['X-Gitlab-Tracking-Context']
        options[:x_gitlab_tracking_context] = tracking_context if tracking_context.present?
      end

      def find_resource(resource_id, project_id)
        return unless resource_id
        return find_commit_in_project(resource_id, project_id) if resource_id.model_class == Commit

        resource_id.then { |id| authorized_find!(id: id) }
      end

      def handle_chat_arguments(options)
        thread_id = options.delete(:thread_id)&.model_id
        thread = Gitlab::Llm::ThreadEnsurer.new(current_user).execute(
          thread_id: thread_id,
          conversation_type: options.delete(:conversation_type),
          write_mode: true
        )
        options[:thread] = thread if thread
      rescue RuntimeError => e
        raise Gitlab::Graphql::Errors::ArgumentError, e.message
      end

      def check_feature_flag_enabled!(method)
        return if Gitlab::Llm::Utils::FlagChecker.flag_enabled_for_feature?(method)

        raise_resource_not_available_error! 'required feature flag is disabled.'
      end

      def verify_rate_limit!
        throttled = Gitlab::ApplicationRateLimiter.throttled?(:ai_action, scope: { user: current_user }) ||
          ::Ai::UsersPerIpLimit.new(user: current_user, request: context[:request]).throttled?
        return unless throttled

        raise_resource_not_available_error! ::Gitlab::ApplicationRateLimiter.throttled_error_message
      end

      def methods(args)
        args.slice(*::Gitlab::Llm::Utils::AiFeaturesCatalogue.external.keys)
      end

      def find_object(id:)
        GitlabSchema.object_from_id(id, expected_type: ::Ai::Model)
      end

      def authorized_resource?(object)
        return unless object

        Ability.allowed?(current_user, "read_#{object.to_ability_name}", object)
      end

      def extract_method_params!(attributes)
        options = attributes.extract!(:client_subscription_id, :platform_origin, :project_id,
          :conversation_type, :thread_id, :root_namespace_id)
        methods = methods(attributes.transform_values(&:to_h))

        # At this point, we only have one method since we filtered it in `#ready?`
        # so we can safely get the first.
        method = methods.each_key.first
        method_arguments = options.merge(methods[method])

        [method_arguments.delete(:resource_id), method, method_arguments]
      end

      def find_commit_in_project(resource_id, project_id)
        project = authorized_find!(id: project_id)
        return unless project

        project.commit_by(oid: resource_id.model_id)
      end
    end
  end
end
