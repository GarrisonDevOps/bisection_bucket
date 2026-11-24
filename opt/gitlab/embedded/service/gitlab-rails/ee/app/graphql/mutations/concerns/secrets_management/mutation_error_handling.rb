# frozen_string_literal: true

module SecretsManagement
  module MutationErrorHandling
    extend ActiveSupport::Concern
    include ::SecretsManagement::GraphqlErrorHandling
  end
end
