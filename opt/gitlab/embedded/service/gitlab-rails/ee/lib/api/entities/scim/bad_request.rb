# frozen_string_literal: true

module API
  module Entities
    module Scim
      class BadRequest < Error
        STATUS = 400
      end
    end
  end
end
