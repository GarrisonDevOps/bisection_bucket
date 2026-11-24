# frozen_string_literal: true

module API
  module Entities
    class Avatar < Grape::Entity
      expose :avatar_url,
        documentation: { type: 'String', example: 'https://example.com/avatar.png' } do |avatarable, options|
        avatarable.avatar_url(only_path: false, size: options[:size])
      end
    end
  end
end
