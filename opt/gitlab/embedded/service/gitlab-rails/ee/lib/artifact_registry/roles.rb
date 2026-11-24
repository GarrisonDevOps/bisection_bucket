# frozen_string_literal: true

module ArtifactRegistry
  # Resolves Artifact Registry role keys to and from their glaz-roles ids
  # via Gitlab::Glaz.roles (gitlab-glaz >= 2.1.0), which exposes the stable
  # machine-readable `key` of every role.
  module Roles
    require 'gitlab/glaz'

    KEYS = %i[artifact_viewer artifact_contributor artifact_manager artifact_admin].freeze

    def self.uuid_for(role_key)
      key = role_key.to_s.downcase.to_sym
      return unless KEYS.include?(key)

      ids_by_key[key]
    end

    def self.name_for(role_id)
      key = keys_by_id[role_id]
      key if KEYS.include?(key)
    end

    def self.ids_by_key
      @ids_by_key ||= ::Gitlab::Glaz.roles.to_h { |role| [role[:key].to_sym, role[:id]] }
    end
    private_class_method :ids_by_key

    def self.keys_by_id
      @keys_by_id ||= ::Gitlab::Glaz.roles.to_h { |role| [role[:id], role[:key].to_sym] }
    end
    private_class_method :keys_by_id
  end
end
