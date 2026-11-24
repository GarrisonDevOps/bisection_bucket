# frozen_string_literal: true

module API
  module Entities
    class BatchBlob < Grape::Entity
      expose :path,
        documentation: { type: 'String', example: 'app/models/user.rb', desc: 'Path of the file in the repository.' }
      expose :commit_id, as: :ref,
        documentation: { type: 'String', example: 'main', desc: 'Branch, tag, or commit the file was read from.' }
      expose :size, documentation: { type: 'Integer', example: 1476, desc: 'Full size of the blob in bytes.' }
      expose :truncated?, as: :truncated, documentation: {
        type: 'Boolean', example: false, desc: 'Whether `content` is truncated to the first 1 MB of the blob.'
      }
      expose :encoding,
        documentation: { type: 'String', example: 'base64', desc: 'Encoding of `content`. Always `base64`.' }
      expose :content,
        documentation: { type: 'String', example: 'VGhpcyBpcyBhIGZpbGU=', desc: 'Base64-encoded content of the blob.' }

      private

      def encoding
        'base64'
      end

      def content
        Base64.strict_encode64(object.data)
      end
    end
  end
end
