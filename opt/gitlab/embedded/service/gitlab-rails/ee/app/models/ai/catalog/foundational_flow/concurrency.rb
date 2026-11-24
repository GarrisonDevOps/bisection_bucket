# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      # A flow's `concurrency` declaration. See doc/development/ai_features/foundational_flows.md.
      class Concurrency
        attr_reader :config

        def initialize(config)
          @config = config
        end

        def declared?
          config.present?
        end

        # Whether the limit applies on resources of the container: the flow declares it, and its
        # feature flag, if any, is on.
        def enabled_for?(container)
          return false unless declared?

          flag = option(:feature_flag)
          return true if flag.nil?

          # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- Need to check the flag defined by flow dynamically.
          ::Feature.enabled?(flag.to_sym, container) ||
            ::Feature.enabled?(flag.to_sym, container.root_ancestor)
          # rubocop:enable Gitlab/FeatureFlagKeyDynamic
        end

        def live_statuses
          Array(option(:live_statuses)).map(&:to_sym)
        end

        def tracks_revision?
          option(:revision_resolver).present?
        end

        def supersede?
          option(:supersede) == true
        end

        def revision_for(resource)
          option(:revision_resolver)&.call(resource: resource)
        end

        private

        def option(key)
          config[key] if config.is_a?(Hash)
        end
      end
    end
  end
end
