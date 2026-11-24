# frozen_string_literal: true

module API
  module Entities
    class IssuableMetricImage < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :created_at, documentation: { type: 'DateTime', example: '2022-01-31T15:10:45.080Z' }
      expose :filename, documentation: { type: 'String', example: 'image.png' }
      expose :file_path,
        documentation: { type: 'String', example: '/uploads/-/system/issuable_metric_image/file/1/image.png' }
      expose :url, documentation: { type: 'String', example: 'https://gitlab.example.com/example' }
      expose :url_text, documentation: { type: 'String', example: 'Example URL' }
    end
  end
end
