# frozen_string_literal: true

module WorkItems
  module Statuses
    # Not an ancestor class but a module because system-defined status isn't a model.
    # Using a shared module allows us to use it as an interface for GraphQL GlobalID input validation.
    # We're not using `BaseStatus` here because it's not a class.
    module Status
    end
  end
end
