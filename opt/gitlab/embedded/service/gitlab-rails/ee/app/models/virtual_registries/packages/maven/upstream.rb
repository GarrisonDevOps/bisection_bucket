# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class Upstream < ApplicationRecord
        include VirtualRegistries::Remote
        include Gitlab::SQL::Pattern
        include Gitlab::Utils::StrongMemoize

        TEST_PATH = 'com/company/app/maven-metadata.xml'
        MAVEN_CENTRAL_URL = 'https://repo1.maven.org/maven2'
        TRAILING_SLASHES_REGEX = %r{/+$}
        DEFAULT_PORTS = { 'https' => 443, 'http' => 80 }.freeze

        SAME_URL_AND_CREDENTIALS_ERROR = 'already has a remote upstream with the same url and credentials'

        belongs_to :group
        has_many :registry_upstreams,
          class_name: 'VirtualRegistries::Packages::Maven::RegistryUpstream',
          inverse_of: :upstream,
          autosave: true
        has_many :registries, class_name: 'VirtualRegistries::Packages::Maven::Registry', through: :registry_upstreams
        has_many :cache_entries,
          class_name: 'VirtualRegistries::Packages::Maven::Cache::Remote::Entry',
          inverse_of: :upstream
        has_many :rules,
          class_name: 'VirtualRegistries::Packages::Maven::Upstream::Rule',
          inverse_of: :remote_upstream

        has_many :allow_rules,
          -> { allowed },
          class_name: 'VirtualRegistries::Packages::Maven::Upstream::Rule',
          inverse_of: :remote_upstream
        has_many :deny_rules,
          -> { denied },
          class_name: 'VirtualRegistries::Packages::Maven::Upstream::Rule',
          inverse_of: :remote_upstream

        encrypts :username, :password

        validates :group, top_level_group: true, presence: true
        validates :url, presence: true, length: { maximum: 255 }
        validates :username, :password, length: { maximum: 2048 }
        validates :cache_validity_hours, numericality: { greater_than_or_equal_to: 0, only_integer: true }
        validates :metadata_cache_validity_hours, numericality: { greater_than: 0, only_integer: true }
        validates :name, presence: true, length: { maximum: 255 }
        validates :description, length: { maximum: 1024 }
        validate :credentials_uniqueness_for_group, if: -> { %i[url username password].any? { |f| changes.key?(f) } }

        validates :url, addressable_url: {
          allow_localhost: false,
          allow_local_network: false,
          dns_rebind_protection: true,
          enforce_sanitization: true
        }
        validates :username, presence: true, if: :password?
        validates :password, presence: true, if: :username?

        before_validation :normalize_url, if: :url?
        before_validation :set_cache_validity_hours_for_maven_central, if: :url?, on: :create
        before_validation :restore_password!, if: -> { username? && !password? && !username_changed? },
          on: :update

        after_validation :reset_credentials, if: -> { persisted? && url_changed? }

        prevent_from_serialization(:password) if respond_to?(:prevent_from_serialization)

        scope :eager_load_registry_upstream, ->(registry:) {
          eager_load(:registry_upstreams)
            .where(registry_upstreams: { registry: })
            .order('registry_upstreams.position ASC')
        }

        scope :for_group, ->(group) { where(group:) }
        scope :for_url, ->(url) { where(url:) }
        scope :for_id_and_group, ->(id:, group:) { where(id:, group:) }
        scope :search_by_name, ->(query) { fuzzy_search(query, [:name], use_minimum_char_limit: false) }

        def self.declarative_policy_class
          'VirtualRegistries::Policies::GroupPolicy'
        end

        def url_for(path)
          full_url = File.join(url, path)
          Addressable::URI.parse(full_url).to_s
        end

        def headers(_ = nil)
          return {} unless username.present? && password.present?

          authorization = ActionController::HttpAuthentication::Basic.encode_credentials(username, password)

          { Authorization: authorization }
        end

        def default_cache_entries
          cache_entries.for_group(group_id).default
        end

        def object_storage_key
          hash = Digest::SHA2.hexdigest(SecureRandom.uuid)
          Gitlab::HashedPath.new(
            'virtual_registries',
            'packages',
            'maven',
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

        def purge_cache!
          ::VirtualRegistries::Cache::MarkEntriesForDestructionWorker.perform_async(to_global_id.to_s)
        end

        def test
          relative_path = new_record? ? TEST_PATH : (default_cache_entries.pick(:relative_path) || TEST_PATH)

          response = Gitlab::HTTP.head(
            url_for(relative_path),
            headers: headers,
            follow_redirects: true
          )

          case response.code
          when 404, 200..299 then { success: true }
          else
            { success: false, result: "Error: #{response.code} - #{response.message}" }
          end
        rescue *::Gitlab::HTTP::HTTP_ERRORS => e
          { success: false, result: "Error: #{e.message}" }
        end

        def destroy_and_sync_positions
          transaction do
            ::VirtualRegistries::Packages::Maven::RegistryUpstream.sync_higher_positions(registry_upstreams)
            destroy
          end
        end

        private

        def normalize_url
          uri = URI.parse(url.strip)

          saved_userinfo = uri.userinfo

          uri.host = uri.host&.downcase

          uri.path = uri.path
            .sub(TRAILING_SLASHES_REGEX, '')
            .chomp('.git')
            .sub(TRAILING_SLASHES_REGEX, '')

          uri.port = nil if uri.port == DEFAULT_PORTS[uri.scheme]

          uri.userinfo = saved_userinfo if saved_userinfo

          self.url = uri.to_s
        rescue URI::InvalidURIError => e
          Gitlab::AppLogger.warn(
            message: 'Failed to normalize upstream URL',
            url: url,
            error: e.message
          )
        end

        def protocol_variant_url
          return unless url.present?

          case url
          when /\Ahttps:/
            url.sub(/\Ahttps:/, 'http:')
          when /\Ahttp:/
            url.sub(/\Ahttp:/, 'https:')
          end
        end

        def credentials_match?(other)
          other.username == username &&
            Rack::Utils.secure_compare(other.password.to_s, password.to_s)
        end

        def reset_credentials
          return if username_changed? && password_changed?

          self.username = nil
          self.password = nil
        end

        def set_cache_validity_hours_for_maven_central
          return unless url.start_with?(MAVEN_CENTRAL_URL)

          self.cache_validity_hours = 0
        end

        def credentials_uniqueness_for_group
          return unless group

          urls_to_check = [url, protocol_variant_url].compact.uniq

          existing_match = self.class.for_group(group)
            .where(url: urls_to_check)
            .then { |q| new_record? ? q : q.where.not(id:) }
            .find { |upstream| credentials_match?(upstream) }

          return unless existing_match

          errors.add(:group, SAME_URL_AND_CREDENTIALS_ERROR)
        end
      end
    end
  end
end
