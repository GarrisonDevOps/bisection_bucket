# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Npm
      class Upstream < ApplicationRecord
        include Gitlab::Utils::StrongMemoize

        ignore_columns %i[username password], remove_with: '18.11', remove_after: '2026-03-14'

        NPMJS_REGISTRY_URL = 'https://registry.npmjs.org'
        TRAILING_SLASHES_REGEX = %r{/+$}

        SAME_URL_AND_CREDENTIALS_ERROR = 'already has a remote upstream with the same url and credentials'
        SAME_LOCAL_PROJECT_OR_GROUP_ERROR = 'already has a local upstream with the same target project or group'

        ALLOWED_GLOBAL_ID_CLASSES = [::Project, ::Group].freeze

        belongs_to :group

        has_many :registry_upstreams,
          class_name: 'VirtualRegistries::Packages::Npm::RegistryUpstream',
          inverse_of: :upstream,
          autosave: true
        has_many :registries, class_name: 'VirtualRegistries::Packages::Npm::Registry', through: :registry_upstreams
        has_many :cache_local_entries,
          class_name: 'VirtualRegistries::Packages::Npm::Cache::Local::Entry',
          inverse_of: :upstream
        has_many :cache_remote_entries,
          class_name: 'VirtualRegistries::Packages::Npm::Cache::Remote::Entry',
          inverse_of: :upstream

        encrypts :auth_token

        validates :group, top_level_group: true, presence: true
        validates :url, presence: true, length: { maximum: 255 }
        validates :auth_token, length: { maximum: 2048 }
        validates :cache_validity_hours, numericality: { greater_than_or_equal_to: 0, only_integer: true }
        validates :metadata_cache_validity_hours, numericality: { greater_than: 0, only_integer: true }
        validates :name, presence: true, length: { maximum: 255 }
        validates :description, length: { maximum: 1024 }
        validate :credentials_uniqueness_for_group, if: -> { %i[url auth_token].any? { |f| changes.key?(f) } }

        # remote validations
        validates :url, addressable_url: {
          allow_localhost: false,
          allow_local_network: false,
          dns_rebind_protection: true,
          enforce_sanitization: true
        }, if: :remote?

        # local validations
        with_options if: :local? do
          validates :auth_token, absence: true
          validate :ensure_local_project_or_local_group
        end

        before_validation :normalize_url, if: -> { url? && remote? }
        after_validation :reset_credentials, if: -> { persisted? && url_changed? }

        prevent_from_serialization(:auth_token)

        scope :for_group, ->(group) { where(group:) }

        def self.declarative_policy_class
          'VirtualRegistries::Policies::GroupPolicy'
        end

        def url=(value)
          super

          clear_memoization(:local_global_id)
        end

        def local?
          !!url&.start_with?('gid://')
        end

        def remote?
          !local?
        end

        def default_cache_entries
          cache_remote_entries.for_group(group_id).default
        end

        def object_storage_key
          hash = Digest::SHA2.hexdigest(SecureRandom.uuid)
          Gitlab::HashedPath.new(
            self.class.module_parent_name.underscore,
            group_id,
            'upstream',
            id,
            'cache',
            'entry',
            hash[0..1],
            hash[2..3],
            hash[4..],
            root_hash: group_id
          ).to_s
        end

        def url_for(path)
          return unless remote?

          full_url = File.join(url, path)
          Addressable::URI.parse(full_url).to_s
        end

        def headers(_ = nil)
          return {} unless auth_token.present?

          { Authorization: "Bearer #{auth_token}" }
        end

        private

        def normalize_url
          self.url = url.sub(TRAILING_SLASHES_REGEX, '')
        end

        def reset_credentials
          return if auth_token_changed?

          self.auth_token = nil
        end

        def credentials_uniqueness_for_group
          return unless group

          return if self.class.for_group(group)
            .select(:auth_token)
            .then { |q| new_record? ? q : q.where.not(id:) }
            .where(url:)
            .none? { |u| Rack::Utils.secure_compare(u.auth_token.to_s, auth_token.to_s) }

          errors.add(:group, remote? ? SAME_URL_AND_CREDENTIALS_ERROR : SAME_LOCAL_PROJECT_OR_GROUP_ERROR)
        end

        def ensure_local_project_or_local_group
          unless local_global_id.model_class.in?(ALLOWED_GLOBAL_ID_CLASSES)
            return errors.add(:url, 'should point to a Project or Group')
          end

          return if local_global_id.model_class.exists?(local_global_id.model_id)

          errors.add(:url, "should point to an existing #{local_global_id.model_class.name}")
        end

        def local_global_id
          GlobalID.parse(url)
        end
        strong_memoize_attr :local_global_id
      end
    end
  end
end
