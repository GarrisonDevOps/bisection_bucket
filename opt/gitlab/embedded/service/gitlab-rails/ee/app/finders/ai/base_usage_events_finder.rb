# frozen_string_literal: true

module Ai
  class BaseUsageEventsFinder
    def initialize(current_user, from:, to:, namespace:, events: nil, users: nil)
      @current_user = current_user
      @from = from
      @to = to
      @events = events
      @namespace = namespace
      @users = users
    end

    def execute
      raise NotImplementedError, "Subclasses must implement #execute"
    end

    private

    attr_reader :current_user, :from, :to, :events, :namespace, :users
  end
end
