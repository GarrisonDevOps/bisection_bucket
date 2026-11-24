# frozen_string_literal: true

module EE
  module Types
    module Ci
      module RunnerManagerType
        extend ActiveSupport::Concern

        RUNNER_UPGRADE_STATUS_TRANSLATIONS = {
          error: nil
        }.freeze

        prepended do
          # NOTE: instance runners are exposed by default to any authenticated user,
          # remember to protect any sensitive fields
          field :upgrade_status, ::Types::Ci::RunnerUpgradeStatusEnum,
            null: true,
            description: 'Availability of upgrades for the runner manager.'

          def upgrade_status
            return unless upgrade_status_available?

            with_cached_attributes do |manager|
              _, status = ::Gitlab::Ci::RunnerUpgradeCheck.new(::Gitlab::VERSION)
                .check_runner_upgrade_suggestion(manager.version)
              RUNNER_UPGRADE_STATUS_TRANSLATIONS.fetch(status, status)
            end
          end

          private

          def upgrade_status_available?
            return false unless ::Gitlab::Ci::RunnerReleases.instance.enabled?

            Ability.allowed?(current_user, :read_runner_upgrade_status)
          end
        end
      end
    end
  end
end
