# frozen_string_literal: true

module Ai
  module Conversations
    class ThreadFinder
      def initialize(current_user, params = {})
        @current_user = current_user
        @params = params
      end

      def execute
        relation = current_user.ai_conversation_threads
        relation = by_id(relation)
        relation = by_conversation_type(relation)
        relation.ordered
      end

      private

      attr_reader :current_user, :params

      def by_id(relation)
        return relation unless params[:id]

        relation.id_in(params[:id])
      end

      def by_conversation_type(relation)
        return relation unless params[:conversation_type]

        relation.for_conversation_type(params[:conversation_type])
      end
    end
  end
end
