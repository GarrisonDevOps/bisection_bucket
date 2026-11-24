# frozen_string_literal: true

module EE
  module Gitlab
    module EventStore
      extend ActiveSupport::Concern

      EE_SUBSCRIPTION_GROUPS = [
        ::Gitlab::EventStore::Subscriptions::AiSubscriptions,
        ::Gitlab::EventStore::Subscriptions::AnalyticsSubscriptions,
        ::Gitlab::EventStore::Subscriptions::AppSecSubscriptions,
        ::Gitlab::EventStore::Subscriptions::CdSubscriptions,
        ::Gitlab::EventStore::Subscriptions::DependencyManagementSubscriptions,
        ::Gitlab::EventStore::Subscriptions::GeoSubscriptions,
        ::Gitlab::EventStore::Subscriptions::GitlabSubscriptionsSubscriptions,
        ::Gitlab::EventStore::Subscriptions::LlmSubscriptions,
        ::Gitlab::EventStore::Subscriptions::McpServerSubscriptions,
        ::Gitlab::EventStore::Subscriptions::PackageMetadataSubscriptions,
        ::Gitlab::EventStore::Subscriptions::PullMirrorsSubscriptions,
        ::Gitlab::EventStore::Subscriptions::SbomSubscriptions,
        ::Gitlab::EventStore::Subscriptions::SearchSubscriptions,
        ::Gitlab::EventStore::Subscriptions::SecuritySubscriptions,
        ::Gitlab::EventStore::Subscriptions::VirtualRegistriesSubscriptions,
        ::Gitlab::EventStore::Subscriptions::VulnerabilitiesSubscriptions
      ].freeze

      class_methods do
        extend ::Gitlab::Utils::Override

        override :subscription_groups
        def subscription_groups
          super + EE_SUBSCRIPTION_GROUPS
        end
      end
    end
  end
end
