# frozen_string_literal: true

module API
  module Entities
    class LegacyEpicNote < ::API::Entities::Note
      expose :noteable_type, documentation: { type: 'String', example: 'Epic' } do |_note, _options|
        'Epic'
      end

      expose :noteable_id, documentation: { type: 'Integer', format: 'int64', example: 1 } do |_note, options|
        options[:epic].id
      end

      expose :noteable_work_item_id, documentation: { type: 'Integer', format: 'int64', example: 1 } do |_note, options|
        options[:epic].issue_id
      end
    end
  end
end
