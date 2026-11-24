# frozen_string_literal: true

module Ai
  module AiResource
    class WorkItem < Ai::AiResource::Issue
      def serialize_for_ai(content_limit: default_content_limit)
        synced_epic = resource.synced_epic
        if synced_epic
          ::EpicSerializer.new(current_user: current_user) # rubocop: disable CodeReuse/Serializer -- we need to serialize resource here
                          .represent(synced_epic, {
                            user: current_user,
                            notes_limit: content_limit,
                            serializer: 'ai',
                            resource: self
                          })
        else
          super
        end
      end

      def current_page_type
        'work_item'
      end

      def chat_questions
        return Ai::AiResource::Epic::CHAT_QUESTIONS if epic_work_item?

        super
      end

      def chat_unit_primitive
        return Ai::AiResource::Epic::CHAT_UNIT_PRIMITIVE if epic_work_item?

        super
      end

      private

      def epic_work_item?
        resource.epic_work_item?
      end
    end
  end
end
