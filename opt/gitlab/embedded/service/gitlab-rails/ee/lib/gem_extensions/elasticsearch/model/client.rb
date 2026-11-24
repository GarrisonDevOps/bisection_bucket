# frozen_string_literal: true

# Override `__elasticsearch__.client` to
# return a client configured from application settings. All including
# classes will use the same instance, which is refreshed automatically
# if the settings change.
#
# when operation is `:search`, the client's retry_on_failure is set to the elasticsearch_retry_on_failure setting.
module GemExtensions
  module Elasticsearch
    module Model
      module Client
        CLIENT_MUTEX = Mutex.new

        cattr_accessor :cached_client
        cattr_accessor :cached_search_client
        cattr_accessor :cached_config
        cattr_accessor :cached_retry_on_failure

        def client(operation = :general)
          store = ::GemExtensions::Elasticsearch::Model::Client

          store::CLIENT_MUTEX.synchronize do
            config = ::Gitlab::CurrentSettings.elasticsearch_config
            retry_on_failure = ::Gitlab::CurrentSettings.elasticsearch_retry_on_failure

            if should_build_clients?(store: store, config: config, retry_on_failure: retry_on_failure)
              search_config = config.deep_dup.merge(retry_on_failure: retry_on_failure)
              store.cached_client = ::Search::Elastic::Client.build(config.deep_dup)
              store.cached_search_client = ::Search::Elastic::Client.build(search_config)
              store.cached_config = config
              store.cached_retry_on_failure = retry_on_failure
            end
          end

          operation == :search ? store.cached_search_client : store.cached_client
        end

        private

        def should_build_clients?(store:, config:, retry_on_failure:)
          store.cached_client.nil? ||
            store.cached_search_client.nil? ||
            config != store.cached_config ||
            retry_on_failure != store.cached_retry_on_failure
        end
      end
    end
  end
end
