# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module CiConfigurationMetadata
      # Internal-only key used to carry security policy metadata (e.g. policy project IDs,
      # scan profile IDs) through ScanPipelineService alongside job configs. This field is
      # consumed by PipelineContext classes to track which jobs were injected and by which
      # policy/profile, then stripped by the Processor before the config is finalized.
      # It must never leak into the actual CI config.
      METADATA_KEY = :_security_metadata_context

      def merge_configuration_metadata!(config, metadata)
        return config if metadata.nil?

        config[METADATA_KEY] = metadata
      end
    end
  end
end
