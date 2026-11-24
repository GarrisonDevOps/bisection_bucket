# frozen_string_literal: true

module Resolvers
  module Ai
    module Conversations
      class TitleResolver < BaseResolver
        type GraphQL::Types::String, null: false

        alias_method :thread, :object

        def resolve
          return unless thread.instance_of?(::Ai::Conversation::Thread)

          BatchLoader::GraphQL.for(thread.id).batch do |thread_ids, loader|
            messages_by_thread = ::Ai::Conversation::Message.for_thread(thread_ids).ordered.group_by(&:thread_id)

            thread_ids.each do |thread_id|
              loader.call(thread_id, messages_by_thread[thread_id]&.first&.content)
            end
          end
        end
      end
    end
  end
end
