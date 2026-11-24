# frozen_string_literal: true

# Default policy definition for nil values
module DeclarativePolicy
  class NilPolicy < DeclarativePolicy::Base
    rule { default }.prevent_all
  end
end
