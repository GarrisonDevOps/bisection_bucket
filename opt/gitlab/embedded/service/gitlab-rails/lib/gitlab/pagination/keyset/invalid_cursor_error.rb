# frozen_string_literal: true

module Gitlab
  module Pagination
    module Keyset
      # Raised when a cursor's attributes do not match the relation's order. Subclasses RuntimeError
      # so existing callers that rescue the bare error keep working.
      InvalidCursorError = Class.new(RuntimeError)
    end
  end
end
