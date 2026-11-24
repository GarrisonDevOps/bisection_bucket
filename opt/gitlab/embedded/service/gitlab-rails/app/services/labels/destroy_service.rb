# frozen_string_literal: true

module Labels
  class DestroyService < Labels::BaseService
    prepend RateLimitedService

    # Destroying a label deletes one label link per linked issuable inside one transaction, so the limit
    # bounds how often one user can replay that. Lives here so the REST API and the web UI share it.
    rate_limit key: :label_delete, opts: { scope: { user: :current_user } }

    attr_reader :current_user, :label

    def initialize(current_user, label)
      @current_user = current_user
      @label = label
    end

    def execute
      @label.destroy
      @label
    end
  end
end

Labels::DestroyService.prepend_mod
