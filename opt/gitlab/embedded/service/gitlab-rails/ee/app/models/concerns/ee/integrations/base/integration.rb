# frozen_string_literal: true

module EE
  module Integrations
    module Base
      module Integration
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          scope :vulnerability_hooks, -> { where(vulnerability_events: true).active }
        end

        EE_INTEGRATION_NAMES = %w[
          google_cloud_platform_workload_identity_federation
          git_guardian
        ].freeze

        EE_PROJECT_LEVEL_ONLY_INTEGRATION_NAMES = %w[
          github
          google_cloud_platform_artifact_registry
        ].freeze

        EE_INSTANCE_LEVEL_ONLY_INTEGRATION_NAMES = %w[
          amazon_q
        ].freeze

        GOOGLE_CLOUD_PLATFORM_INTEGRATION_NAMES = %w[
          google_cloud_platform_artifact_registry
          google_cloud_platform_workload_identity_federation
        ].freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :active
          def active(*_args)
            return super if instance_allows_all_integrations?

            allowed_integration_types = ::Gitlab::CurrentSettings.allowed_integrations.map do |name|
              integration_name_to_type(name)
            end

            super.where(type: allowed_integration_types)
          end

          override :integration_names
          def integration_names
            names = super + EE_INTEGRATION_NAMES

            unless ::Gitlab::Saas.feature_available?(:google_cloud_support)
              names.delete('google_cloud_platform_workload_identity_federation')
            end

            names
          end

          override :instance_specific_integration_names
          def instance_specific_integration_names
            EE_INSTANCE_LEVEL_ONLY_INTEGRATION_NAMES + super
          end

          override :disabled_integration_names
          def disabled_integration_names
            disabled = super
            disabled += ['amazon_q'] unless ::Ai::AmazonQ.feature_available?
            disabled
          end

          override :project_specific_integration_names
          def project_specific_integration_names
            names = super + EE_PROJECT_LEVEL_ONLY_INTEGRATION_NAMES

            unless ::Gitlab::Saas.feature_available?(:google_cloud_support)
              names.delete('google_cloud_platform_artifact_registry')
            end

            names
          end

          override :available_integration_names
          def available_integration_names(include_blocked_by_settings: false, **kwargs)
            names = super(**kwargs)

            return names if include_blocked_by_settings || instance_allows_all_integrations?

            names & ::Gitlab::CurrentSettings.allowed_integrations
          end

          # Returns the STI type for the given integration name.
          # Example: "asana" => "Integrations::Asana"
          override :integration_name_to_type
          def integration_name_to_type(name)
            name = name.to_s

            if GOOGLE_CLOUD_PLATFORM_INTEGRATION_NAMES.include?(name)
              name = name.delete_prefix("google_cloud_platform_")
              "Integrations::GoogleCloudPlatform::#{name.camelize}"
            else
              super
            end
          end

          override :all_integration_names
          def all_integration_names
            available_integration_names(include_disabled: true, include_blocked_by_settings: true)
          end

          def blocked_by_settings?(log: false)
            return false if instance_allows_all_integrations?

            ::Gitlab::CurrentSettings.allowed_integrations.exclude?(to_param).tap do |is_blocked|
              ::Gitlab::IntegrationsLogger.info(message: "#{title} blocked by settings") if is_blocked && log
            end
          end

          private

          def instance_allows_all_integrations?
            ::Gitlab::CurrentSettings.allow_all_integrations? || !::License.feature_available?(:integrations_allow_list)
          end
        end

        delegate :blocked_by_settings?, to: :class

        def active
          super && !blocked_by_settings?
        end

        override :testable?
        def testable?
          super && !blocked_by_settings?
        end
      end
    end
  end
end
