# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Settings
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          private

          override :available_stages
          def available_stages(current_user, oauth: false)
            return super unless oauth && continuous_sync_offered?(current_user)

            super.merge(self::OPTIONAL_STAGES.slice(:continuous_sync))
          end

          # On GitLab.com, the license is enforced per destination namespace on submit, so the
          # checkbox isn't gated on the instance license. On self-managed, there's no per-namespace
          # plan to defer to, so the instance-wide license decides upfront.
          def continuous_sync_offered?(current_user)
            return false unless ::Feature.enabled?(:github_continuous_import, current_user)

            ::Gitlab.com? || # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- namespace isn't known yet; license is enforced per-namespace on submit instead
              ::License.feature_available?(:github_continuous_sync)
          end
        end
      end
    end
  end
end
