# frozen_string_literal: true

module API
  module Entities
    class UserStatus < Grape::Entity
      expose :emoji, documentation: { type: 'String', example: 'coffee' }
      expose :message, documentation: { type: 'String', example: 'I crave coffee' }
      expose :availability, documentation: { type: 'String', example: 'busy' }
      expose :message_html, documentation: { type: 'String', example: '<p dir="auto">I crave coffee</p>' } do |entity|
        MarkupHelper.markdown_field(entity, :message)
      end
      expose :clear_status_at, documentation: { type: 'DateTime', example: '2026-10-28T10:00:00.000Z' }
    end
  end
end
