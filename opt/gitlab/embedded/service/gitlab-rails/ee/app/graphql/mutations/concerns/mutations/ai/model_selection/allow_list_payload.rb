# frozen_string_literal: true

module Mutations
  module Ai
    module ModelSelection
      # Shared by the instance- and namespace-level model selection allowlist update
      # mutations, which decorate the updated feature setting identically.
      module AllowListPayload
        private

        def allow_list_payload(result)
          return if result.error?

          decorated = ::Gitlab::Graphql::Representation::ModelSelection::FeatureSetting.decorate(
            [result.payload],
            current_user: current_user
          ).first

          decorated&.allow_list
        end
      end
    end
  end
end
