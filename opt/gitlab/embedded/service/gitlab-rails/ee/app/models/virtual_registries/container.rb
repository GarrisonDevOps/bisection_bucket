# frozen_string_literal: true

module VirtualRegistries
  module Container
    MANIFEST_DIGEST_REGEX = %r{.*/manifests/(#{Gitlab::PathRegex::OCI_DIGEST_REGEX})\z}o
    BLOB_DIGEST_REGEX = %r{.*/blobs/(#{Gitlab::PathRegex::OCI_DIGEST_REGEX})\z}o
    OCI_DIGEST_VALIDATION_REGEX = /\A#{Gitlab::PathRegex::OCI_DIGEST_REGEX}\z/o

    def self.table_name_prefix
      'virtual_registries_container_'
    end

    def self.extract_digest_from_path(path)
      return unless path

      path[MANIFEST_DIGEST_REGEX, 1] || path[BLOB_DIGEST_REGEX, 1]
    end

    def self.sanitize_etag(etag)
      etag&.delete('"')
    end

    def self.feature_prerequisites_met?(group)
      group.dependency_proxy_feature_available? &&
        ::Feature.enabled?(:container_virtual_registries, group) &&
        group.licensed_feature_available?(:container_virtual_registry)
    end

    def self.feature_enabled?(group)
      feature_prerequisites_met?(group) && ::VirtualRegistries::Setting.enabled_for_group?(group)
    end

    def self.virtual_registry_available?(group, current_user, permission = :read_virtual_registry)
      feature_enabled?(group) && ::VirtualRegistries.user_has_access?(group, current_user, permission)
    end
  end
end
