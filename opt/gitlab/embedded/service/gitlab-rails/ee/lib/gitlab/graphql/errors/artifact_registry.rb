# frozen_string_literal: true

module Gitlab
  module Graphql
    module Errors
      module ArtifactRegistry
        ServiceUnavailable = Class.new(::Gitlab::Graphql::Errors::BaseError)
      end
    end
  end
end
