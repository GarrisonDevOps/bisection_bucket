# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Packages
        module Npm
          module Cache
            module Remote
              class Entry < Grape::Entity
                expose :id, documentation: { type: 'String', example: 'MjMgNTAw' } do |cache_entry, _options|
                  cache_entry.generate_id
                end

                expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
                expose :upstream_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
                expose :upstream_checked_at, documentation: { type: 'DateTime' }
                expose :file_md5,
                  documentation: { type: 'String', example: 'd8e8fca2dc0f896fd7cb4cb0031ba249' }
                expose :file_sha1,
                  documentation: { type: 'String', example: '4e1243bd22c66e76c2ba9eddc1f91394e57f9f83' }
                expose :size, documentation: { type: 'Integer', example: 1 }
                expose :relative_path,
                  documentation: { type: 'String',
                                   example: '/@scope/package/-/@scope/package-2026.11.02-t-14.15.3.tgz' }
                expose :upstream_etag,
                  documentation: { type: 'String', example: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c' }
                expose :content_type, documentation: { type: 'String', example: 'application/octet-stream' }
                expose :created_at, documentation: { type: 'DateTime', example: '2025-12-16T13:25:30.029Z' }
                expose :updated_at, documentation: { type: 'DateTime', example: '2025-12-16T13:25:30.029Z' }
                expose :downloads_count, documentation: { type: 'Integer', example: 1 }
                expose :downloaded_at,
                  documentation: { type: 'DateTime', example: '2025-11-11T13:25:29.935Z' }
              end
            end
          end
        end
      end
    end
  end
end
