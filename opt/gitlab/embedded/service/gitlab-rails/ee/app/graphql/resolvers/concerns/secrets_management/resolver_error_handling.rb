# frozen_string_literal: true

module SecretsManagement
  module ResolverErrorHandling
    extend ActiveSupport::Concern

    include ::SecretsManagement::GraphqlErrorHandling
  end
end
