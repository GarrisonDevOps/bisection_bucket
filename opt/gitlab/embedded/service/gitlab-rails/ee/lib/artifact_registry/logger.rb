# frozen_string_literal: true

module ArtifactRegistry
  # Structured logger for artifact registry provisioning and resolution
  # operations, tagged with the artifact_registry feature category.
  class Logger < ::Gitlab::JsonLogger
    def self.file_name_noext
      'artifact_registry'
    end

    private

    def default_attributes
      super.merge(feature_category: :artifact_registry)
    end
  end
end
