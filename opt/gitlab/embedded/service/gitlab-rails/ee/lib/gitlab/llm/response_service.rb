# frozen_string_literal: true

module Gitlab
  module Llm
    class ResponseService < BaseService
      def initialize(context, basic_options)
        @user = context.current_user
        @resource = context.resource
        @basic_options = basic_options
      end

      def execute(response:, options: {}, save_message: true)
        ::Gitlab::Llm::GraphqlSubscriptionResponseService
          .new(user, resource, response,
            options: basic_options.merge(options),
            save_message: save_message)
          .execute
      end

      private

      attr_reader :user, :resource, :basic_options
    end
  end
end
