# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class LlmSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Llm::NamespaceAccessCacheResetWorker, to: ::NamespaceSettings::AiRelatedSettingsChangedEvent
          store.subscribe ::Llm::NamespaceAccessCacheResetWorker, to: ::Members::AddedCloudEvent
        end
      end
    end
  end
end
