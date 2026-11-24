# frozen_string_literal: true

module API
  module Entities
    module Scim
      class Forbidden < Error
        STATUS = 403
      end
    end
  end
end
