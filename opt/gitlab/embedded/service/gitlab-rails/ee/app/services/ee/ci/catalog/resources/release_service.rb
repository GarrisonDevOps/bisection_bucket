# frozen_string_literal: true

module EE
  module Ci
    module Catalog
      module Resources
        module ReleaseService
          extend ::Gitlab::Utils::Override
          include ::Gitlab::InternalEventsTracking

          private

          override :check_project_access
          def check_project_access
            return unless ::License.feature_available?(:ci_cd_catalog_publish_restriction)

            projects_allowlist = ::Gitlab::CurrentSettings.ci_cd_catalog_projects_allowlist
            return if projects_allowlist.blank?
            return if project_in_allowlist?(projects_allowlist)

            track_publish_blocked
            errors << 'The project is not authorized to publish to the CI/CD catalog'
          end

          def track_publish_blocked
            track_internal_event(
              'ci_catalog_publish_blocked_by_allowlist',
              user: user,
              project: project,
              namespace: project.namespace
            )
          end

          def project_in_allowlist?(allowlist)
            project_path = project.full_path

            allowlist.any? do |pattern|
              path_matches_pattern?(project_path, pattern)
            end
          end

          def path_matches_pattern?(path, pattern)
            ::Gitlab::UntrustedRegexp.new("\\A#{pattern}\\z").match?(path)
          rescue RegexpError
            path == pattern
          end
        end
      end
    end
  end
end
