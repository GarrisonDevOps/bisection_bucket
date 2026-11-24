# frozen_string_literal: true

module VirtualRegistries
  module Container
    module Cache
      module Remote
        class Entry < ::VirtualRegistries::Cache::Entry
          include ::UpdateNamespaceStatistics

          self.primary_key = %i[group_id iid]

          belongs_to :upstream,
            class_name: 'VirtualRegistries::Container::Upstream',
            inverse_of: :cache_remote_entries,
            optional: false

          update_namespace_statistics namespace_statistics_name: :dependency_proxy_size

          validates :relative_path,
            uniqueness: { scope: [:upstream_id, :status, :group_id] },
            if: :default?
          validates :digest,
            format: {
              with: VirtualRegistries::Container::OCI_DIGEST_VALIDATION_REGEX,
              message: 'must be a valid OCI digest'
            },
            allow_nil: true

          scope :for_digest, ->(digest) { where(digest:) }
          attribute :file_store, default: -> { VirtualRegistries::Cache::EntryUploader.default_store }

          scope :order_iid_desc, -> { reorder(iid: :desc) }

          def self.declarative_policy_class
            'VirtualRegistries::Policies::GroupPolicy'
          end

          def generate_id
            Base64.urlsafe_encode64("#{group_id} #{iid}")
          end

          def stale?
            return true unless upstream
            return false if upstream.cache_validity_hours == 0

            (upstream_checked_at + upstream.cache_validity_hours.hours).past?
          end

          def digest_addressed?
            VirtualRegistries::Container.extract_digest_from_path(relative_path).present?
          end
        end
      end
    end
  end
end
