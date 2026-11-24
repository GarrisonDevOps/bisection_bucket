# frozen_string_literal: true

module ArtifactRegistry
  module AcceptsRemoteSettings
    extend ActiveSupport::Concern

    included do
      argument :settings, ::Types::ArtifactRegistry::RemoteSettingsInputType,
        required: false,
        validates: { allow_null: false },
        experiment: { milestone: '19.4' },
        description: 'Upstream configuration. Required on a remote repository create, rejected on ' \
          'any other kind.'
    end
  end
end
