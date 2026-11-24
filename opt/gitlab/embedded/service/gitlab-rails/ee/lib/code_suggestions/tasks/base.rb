# frozen_string_literal: true

module CodeSuggestions
  module Tasks
    class Base
      AI_GATEWAY_CONTENT_SIZE = 100_000

      delegate :base_url, :self_hosted?, :feature_setting, :feature_name, :feature_disabled?, :licensed_feature,
        :namespace_feature_setting?, :vendored?, :duo_context_not_found?, :unit_primitive_name, to: :model_details

      def initialize(current_user:, params: {}, unsafe_passthrough_params: {}, client: nil)
        @params = params
        @unsafe_passthrough_params = unsafe_passthrough_params
        @client = client || CodeSuggestions::Client.new({})
        @current_user = current_user
      end

      def body
        body_params = passthrough_params.merge(prompt_request_params)

        trim_content_params(body_params)

        body_params.to_json
      end

      def prompt_request_params
        raise NotImplementedError
      end

      def endpoint
        raise NotImplementedError
      end

      private

      attr_reader :params, :unsafe_passthrough_params, :client, :current_user

      def passthrough_params
        unsafe_passthrough_params
      end

      def model_details
        raise NotImplementedError
      end

      def trim_content_params(body_params)
        return unless body_params[:current_file]

        body_params[:current_file][:content_above_cursor] =
          body_params[:current_file][:content_above_cursor].to_s.last(AI_GATEWAY_CONTENT_SIZE)
        body_params[:current_file][:content_below_cursor] =
          body_params[:current_file][:content_below_cursor].to_s.first(AI_GATEWAY_CONTENT_SIZE)
      end
    end
  end
end
