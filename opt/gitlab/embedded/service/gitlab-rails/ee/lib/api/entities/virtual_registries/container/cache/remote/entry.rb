# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Container
        module Cache
          module Remote
            class Entry < Grape::Entity
              expose :generate_id, as: :id, documentation: { type: 'String', example: 'MjMgNTAw' }
              expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
              expose :upstream_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
              expose :upstream_checked_at, documentation: { type: 'DateTime' }
              expose :file_sha1,
                documentation: { type: 'String', example: '4e1243bd22c66e76c2ba9eddc1f91394e57f9f83' }
              expose :size, documentation: { type: 'Integer', example: 1 }
              expose :relative_path, documentation: { type: 'String', example: 'library/alpine/manifests/latest' }
              expose :upstream_etag,
                documentation: { type: 'String', example: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c' }
              expose :content_type, documentation: { type: 'String', example: 'application/octet-stream' }
              expose :created_at, documentation: { type: 'DateTime', example: '2025-12-16T13:25:30.029Z' }
              expose :updated_at, documentation: { type: 'DateTime', example: '2025-12-16T13:25:30.029Z' }
              expose :downloads_count, documentation: { type: 'Integer', example: 1 }
              expose :downloaded_at, documentation: { type: 'DateTime', example: '2025-11-11T13:25:29.935Z' }
            end
          end
        end
      end
    end
  end
end
