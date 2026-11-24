# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class Registry
        CUSTOMERS_DOT_URL = ::Gitlab::Routing.url_helpers.subscription_portal_url.freeze
        CLOUD_CONNECTOR_URL = ::CloudConnector::Config.base_url.freeze

        def initialize(user)
          @user = user
        end

        # Carries out minimal checks for development and testing purposes
        def development_probes
          [
            ::CloudConnector::StatusChecks::Probes::HostProbe.new(::Gitlab::AiGateway.self_hosted_url),
            ::CloudConnector::StatusChecks::Probes::EndToEndProbe.new(@user)
          ]
        end

        def amazon_q_probes
          [
            ::CloudConnector::StatusChecks::Probes::AmazonQ::EndToEndProbe.new(@user)
          ]
        end

        def self_hosted_probes
          appended_probes = [*duo_agent_platform_probes, *self_hosted_billing_probes]

          base =
            if at_least_one_vendored_feature?
              [
                *probes_for_vendored_features(appended_probes),
                *self_hosted_only_probes
              ]
            else
              [
                *self_hosted_only_probes,
                *offline_vendored_features_probes,
                *foundational_flows_probes
              ]
            end

          [*base, *appended_probes]
        end

        def default_probes
          [
            ::CloudConnector::StatusChecks::Probes::LicenseProbe.new,
            ::CloudConnector::StatusChecks::Probes::HostProbe.new(CUSTOMERS_DOT_URL),
            ::CloudConnector::StatusChecks::Probes::HostProbe.new(CLOUD_CONNECTOR_URL),
            ::CloudConnector::StatusChecks::Probes::AccessProbe.new,
            ::CloudConnector::StatusChecks::Probes::TokenProbe.new,
            ::CloudConnector::StatusChecks::Probes::EndToEndProbe.new(@user),
            *duo_agent_platform_probes,
            *foundational_flows_probes,
            *self_hosted_billing_probes
          ]
        end

        private

        def self_hosted_billing_probes
          return [] unless self_hosted_billing_applicable?

          [
            ::CloudConnector::StatusChecks::Probes::SelfHosted::BillingCustomersDotProbe.new,
            ::CloudConnector::StatusChecks::Probes::SelfHosted::BillingCloudAiGatewayProbe.new,
            ::CloudConnector::StatusChecks::Probes::SelfHosted::BillingDuoWorkflowServiceProbe.new(@user)
          ]
        end

        def self_hosted_billing_applicable?
          ::Ai::SelfHostedDapBilling.self_hosted_dap_billing_enabled? &&
            ::Gitlab::DuoWorkflow::Client.self_hosted_url.present?
        end

        def duo_agent_platform_probes
          probes = []

          unless offline_cloud_license?
            probes << ::CloudConnector::StatusChecks::Probes::DuoAgentPlatformProbe.new(
              @user, deployment: :cloud_connected
            )
          end

          if ::Gitlab::DuoWorkflow::Client.self_hosted_url.present?
            probes << ::CloudConnector::StatusChecks::Probes::DuoAgentPlatformProbe.new(
              @user, deployment: :self_hosted
            )
          end

          probes
        end

        def offline_cloud_license?
          !!::License.current&.offline_cloud_license?
        end

        def foundational_flows_probes
          [
            ::CloudConnector::StatusChecks::Probes::FoundationalFlows::AllowFlowExecutionProbe.new,
            ::CloudConnector::StatusChecks::Probes::FoundationalFlows::AllowFoundationalFlowsProbe.new,
            ::CloudConnector::StatusChecks::Probes::FoundationalFlows::CompatibleRunnerProbe.new
          ]
        end

        def probes_for_vendored_features(appended_probes)
          appended_classes = appended_probes.map(&:class)
          probes = default_probes.reject { |probe| appended_classes.include?(probe.class) }

          return probes if code_completions_is_vendored?

          probes.reject { |probe| probe.is_a?(::CloudConnector::StatusChecks::Probes::EndToEndProbe) }
        end

        def self_hosted_only_probes
          [
            ::CloudConnector::StatusChecks::Probes::SelfHosted::AiGatewayUrlPresenceProbe.new,
            ::CloudConnector::StatusChecks::Probes::HostProbe.new(::Gitlab::AiGateway.self_hosted_url),
            ::CloudConnector::StatusChecks::Probes::SelfHosted::CodeSuggestionsLicenseProbe.new(@user)
          ]
        end

        def offline_vendored_features_probes
          return [] unless offline_cloud_license?
          return [] if ::Ai::FeatureSetting.select_allowed(::Ai::FeatureSetting.vendored).empty?

          [::CloudConnector::StatusChecks::Probes::SelfHosted::VendoredFeaturesProbe.new]
        end

        def at_least_one_vendored_feature?
          return false if offline_cloud_license?

          ::Ai::FeatureSetting.vendored.exists? ||
            ::Ai::ModelSelection::InstanceModelSelectionFeatureSetting.exists?
        end

        def code_completions_is_vendored?
          ::Ai::FeatureSettingSelectionService
                  .new(
                    @user,
                    :code_completions,
                    nil
                  ).execute.payload&.vendored?
        end
      end
    end
  end
end
