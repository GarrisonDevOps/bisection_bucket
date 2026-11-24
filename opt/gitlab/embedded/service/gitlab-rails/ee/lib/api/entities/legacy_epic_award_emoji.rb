# frozen_string_literal: true

module API
  module Entities
    class LegacyEpicAwardEmoji < ::API::Entities::AwardEmoji
      expose :awardable_type, documentation: { type: 'String', example: 'Epic' } do |_award, _options|
        'Epic'
      end

      expose :awardable_id, documentation: { type: 'Integer', format: 'int64', example: 1 } do |_award, options|
        options[:epic].id
      end

      expose :awardable_work_item_id,
        documentation: { type: 'Integer', format: 'int64', example: 1 } do |_award, options|
        options[:epic].issue_id
      end
    end
  end
end
