# frozen_string_literal: true

module EE
  module API
    module Ci
      module Helpers
        module Runner
          extend ::Gitlab::Utils::Override

          override :track_ci_minutes_usage!
          def track_ci_minutes_usage!(build)
            ::Ci::Minutes::TrackLiveConsumptionService.new(build).execute
          end

          override :audit_download
          def audit_download(build, filename)
            super

            ::Ci::ArtifactDownloadAuditor.new(
              current_user: current_user,
              build: build,
              filename: filename
            ).execute
          end
        end
      end
    end
  end
end
