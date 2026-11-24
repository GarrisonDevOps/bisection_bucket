# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Container
        module Cache
          class Entry < Grape::Entity
            expose :id, documentation: { type: 'String' } do |cache_entry, _options|
              cache_entry.generate_id
            end

            expose :group_id, documentation: { type: 'Integer' }
            expose :upstream_id, documentation: { type: 'Integer' }
            expose :upstream_checked_at, documentation: { type: 'DateTime' }
            expose :file_sha1, documentation: { type: 'String' }
            expose :size, documentation: { type: 'Integer' }
            expose :relative_path, documentation: { type: 'String' }
            expose :upstream_etag, documentation: { type: 'String' }
            expose :content_type, documentation: { type: 'String' }
            expose :created_at, documentation: { type: 'DateTime' }
            expose :updated_at, documentation: { type: 'DateTime' }
            expose :downloads_count, documentation: { type: 'Integer' }
            expose :downloaded_at, documentation: { type: 'DateTime' }
          end
        end
      end
    end
  end
end
