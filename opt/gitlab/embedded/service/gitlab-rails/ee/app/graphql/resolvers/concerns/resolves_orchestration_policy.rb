# frozen_string_literal: true

module ResolvesOrchestrationPolicy
  extend ActiveSupport::Concern

  included do
    include Gitlab::Graphql::Authorize::AuthorizeResource

    calls_gitaly!

    alias_method :project, :object
  end
end
