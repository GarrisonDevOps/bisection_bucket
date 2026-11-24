# frozen_string_literal: true

module VirtualRegistries
  module Container
    module Cache
      class Entry < ::VirtualRegistries::Cache::Entry
        ignore_column :file_md5, remove_with: '18.9', remove_after: '2026-01-15'

        belongs_to :upstream,
          class_name: 'VirtualRegistries::Container::Upstream',
          optional: false

        def stale?
          return true unless upstream

          return false if upstream.cache_validity_hours == 0

          (upstream_checked_at + upstream.cache_validity_hours.hours).past?
        end
      end
    end
  end
end
