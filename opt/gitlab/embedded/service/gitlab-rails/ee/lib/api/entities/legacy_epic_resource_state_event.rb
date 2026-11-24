# frozen_string_literal: true

module API
  module Entities
    class LegacyEpicResourceStateEvent < ::API::Entities::ResourceStateEvent
      expose :resource_type, documentation: { type: 'String', example: 'Epic' } do |_event, _options|
        'Epic'
      end

      expose :resource_id, documentation: { type: 'Integer', format: 'int64', example: 1 } do |_event, options|
        options[:epic].id
      end

      expose :resource_work_item_id,
        documentation: { type: 'Integer', format: 'int64', example: 1 } do |_event, options|
        options[:epic].issue_id
      end
    end
  end
end
