# frozen_string_literal: true

module Ai
  # Shared behavior for per-user AI memory tables.
  # Including models must define a `belongs_to` for their scoping container
  # (namespace or organization) and a unique index on [container_id, user_id].
  module UserMemoryable
    extend ActiveSupport::Concern

    MAX_CONTENT_LENGTH = 4_000

    included do
      belongs_to :user, optional: false

      validates :content, presence: true, length: { maximum: MAX_CONTENT_LENGTH }
    end
  end
end
