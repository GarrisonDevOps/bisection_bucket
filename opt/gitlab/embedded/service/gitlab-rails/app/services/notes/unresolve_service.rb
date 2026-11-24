# frozen_string_literal: true

module Notes
  class UnresolveService < ::BaseService
    prepend RateLimitedService

    rate_limit key: :discussions_resolve, opts: { scope: { user: :current_user } }

    def execute(note)
      note.unresolve!
    end
  end
end
