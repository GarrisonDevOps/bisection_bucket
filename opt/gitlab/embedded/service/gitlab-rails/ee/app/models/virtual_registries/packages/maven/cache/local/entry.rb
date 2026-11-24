# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Cache
        module Local
          class Entry < ApplicationRecord
            include ::VirtualRegistries::Local

            self.primary_key = %i[group_id iid]

            belongs_to :group
            belongs_to :upstream,
              class_name: 'VirtualRegistries::Packages::Maven::Local::Upstream',
              inverse_of: :cache_entries,
              optional: false
            belongs_to :package_file,
              class_name: 'Packages::PackageFile',
              optional: false

            validates :group, top_level_group: true, presence: true
            validates :relative_path, :upstream_checked_at, presence: true
            validates :relative_path, length: { maximum: 1024 }
            validates :relative_path, format: { without: /\s/, message: 'must not contain spaces' }
            validates :relative_path, uniqueness: { scope: [:upstream_id, :group_id] }, on: %i[create update]

            delegate :file, :file_name, :file_sha1, :file_md5, to: :package_file, allow_nil: true

            scope :for_group, ->(group) { where(group:) }
            scope :for_upstream, ->(upstream) { where(upstream:) }
            scope :preload_package_file, -> { preload(:package_file) }

            def self.declarative_policy_class
              'VirtualRegistries::Policies::GroupPolicy'
            end

            def stale?
              return true unless upstream

              validity_hours = if relative_path.end_with?('maven-metadata.xml')
                                 upstream.metadata_cache_validity_hours
                               else
                                 upstream.cache_validity_hours
                               end

              return false if validity_hours == 0

              (upstream_checked_at + validity_hours.hours).past?
            end

            # Derive from the name: the uploader's content_type sends a HEAD request to object storage.
            def content_type
              ::Gitlab::Utils::MimeType.from_filename(file_name)
            end
          end
        end
      end
    end
  end
end
