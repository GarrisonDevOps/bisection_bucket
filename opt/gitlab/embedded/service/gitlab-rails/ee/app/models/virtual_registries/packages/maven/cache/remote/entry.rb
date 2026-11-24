# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Cache
        module Remote
          class Entry < ApplicationRecord
            include FileStoreMounter
            include Gitlab::SQL::Pattern
            include ::UpdateNamespaceStatistics
            include ShaAttribute
            include CounterAttribute
            include ::Auditable
            include ::VirtualRegistries::Remote

            self.primary_key = %i[group_id iid]

            belongs_to :group, optional: false
            belongs_to :upstream,
              class_name: 'VirtualRegistries::Packages::Maven::Upstream',
              inverse_of: :cache_entries,
              optional: false

            alias_method :namespace, :group

            update_namespace_statistics namespace_statistics_name: :dependency_proxy_size

            enum :status, default: 0, processing: 1, pending_destruction: 2, error: 3

            sha_attribute :file_sha1
            sha_attribute :file_md5

            counter_attribute :downloads_count, touch: :downloaded_at

            validates :group, top_level_group: true
            validates :relative_path,
              :object_storage_key,
              :size,
              :file_sha1,
              presence: true
            validates :upstream_etag, :content_type, length: { maximum: 255 }
            validates :relative_path, :object_storage_key, length: { maximum: 1024 }
            validates :file_md5, length: { is: 32 }, allow_nil: true
            validates :file_sha1, length: { is: 40 }
            validates :relative_path,
              uniqueness: { scope: %i[upstream_id status group_id] },
              if: :default?
            validates :object_storage_key, uniqueness: { scope: %i[relative_path group_id] }
            validates :file, presence: true

            mount_file_store_uploader ::VirtualRegistries::Cache::EntryUploader

            attribute :file_store, default: -> { VirtualRegistries::Cache::EntryUploader.default_store }

            before_validation :set_object_storage_key, if: -> { object_storage_key.blank? && upstream }
            attr_readonly :object_storage_key

            scope :search_by_relative_path, ->(query) do
              fuzzy_search(query, [:relative_path], use_minimum_char_limit: false)
            end
            scope :for_group, ->(group) { where(group:) }
            scope :for_upstream, ->(upstream) { where(upstream:) }
            scope :order_created_desc, -> { reorder(created_at: :desc) }
            scope :order_iid_desc, -> { reorder(iid: :desc) }
            scope :requiring_cleanup, ->(n_days_to_keep) {
              where(downloaded_at: ...(Time.current - n_days_to_keep.days))
            }

            def self.declarative_policy_class
              'VirtualRegistries::Policies::GroupPolicy'
            end

            def self.next_pending_destruction
              pending_destruction.lock('FOR UPDATE SKIP LOCKED').take
            end

            # create or update a cached response identified by the upstream, group_id and relative_path
            # Given that we have chances that this function is not executed in isolation, we can't use
            # safe_find_or_create_by.
            # We are using the check existence and rescue alternative.
            def self.create_or_update_by!(upstream:, group_id:, relative_path:, updates: {})
              default.find_or_initialize_by(
                upstream: upstream,
                group_id: group_id,
                relative_path: relative_path
              ).tap do |record|
                record.update!(**updates)
              end
            rescue ActiveRecord::RecordInvalid => invalid
              # in case of a race condition, retry the block
              retry if invalid.record&.errors&.of_kind?(:relative_path, :taken)

              # otherwise, bubble up the error
              raise
            end

            def generate_id
              Base64.urlsafe_encode64("#{group_id} #{iid}")
            end

            def filename
              return unless relative_path

              File.basename(relative_path)
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

            def bump_downloads_count
              increment_downloads_count(1)
            end

            private

            def set_object_storage_key
              self.object_storage_key = upstream.object_storage_key
            end
          end
        end
      end
    end
  end
end
