# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RemoteSettingsInputType < BaseInputObject
      graphql_name 'ArtifactRegistryRemoteSettingsInput'
      description 'Writable upstream configuration of a remote Artifact Registry repository.'

      argument :url, GraphQL::Types::String,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Base URL of the upstream registry, at most 1024 characters. Changing it resets ' \
          'the health fields, evicts the cached artifacts, and clears the stored credentials unless ' \
          'the same request supplies new ones.'

      argument :cache_validity_hours, GraphQL::Types::Int,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Revalidation window for cached artifacts, in hours. Between 0 and 32767, where ' \
          '0 means cached artifacts never revalidate.'

      argument :metadata_cache_validity_hours, GraphQL::Types::Int,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Revalidation window for cached metadata, in hours. Between 1 and 32767, so ' \
          'metadata always revalidates on a schedule. Maven and npm only; other formats reject it.'

      argument :snapshot_metadata_always_revalidate, GraphQL::Types::Boolean,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Whether snapshot metadata revalidates on every read instead of on the metadata ' \
          'window. Maven only; other formats reject it.'

      argument :credentials, ::Types::ArtifactRegistry::RemoteCredentialsInputType,
        required: false,
        experiment: { milestone: '19.4' },
        description: 'Upstream credentials. Omit to leave the stored ones unchanged, supply an object ' \
          'to replace them, or, on an update, supply null to clear them.'

      # Artifact Registry takes a JSON body, so the mutations forward a Hash
      # rather than this object. to_h unwraps the nested credentials input too.
      #
      # An empty object is refused rather than forwarded: it clears the client's
      # "at least one mutable field" guard, and Artifact Registry answers 200 for
      # a write it did not make.
      def prepare
        to_h.tap do |settings|
          raise GraphQL::ExecutionError, 'settings must carry at least one field' if settings.empty?
        end
      end
    end
  end
end
