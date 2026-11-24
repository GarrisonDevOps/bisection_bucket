# frozen_string_literal: true

module Gitlab
  module Ci
    class ProjectConfig
      class SecurityScanProfile < Gitlab::Ci::ProjectConfig::Source
        def content
          return unless scan_profile_context&.eligible?

          # Empty YAML is enough to trigger pipeline creation. Jobs are added by SecurityScanProfiles::Processor.
          YAML.dump(nil)
        end

        def source
          :security_scan_profiles_source
        end
      end
    end
  end
end
