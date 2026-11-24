# frozen_string_literal: true

module API
  module Entities
    module Scim
      class NotFound < Error
        STATUS = 404
      end
    end
  end
end
