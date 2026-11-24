# frozen_string_literal: true

module ApprovalRules
  class BaseService < BaseContainerService
    MISSING_METHOD_ERROR = Class.new(StandardError)

    def execute
      return access_denied unless skip_authorization || authorized?

      action
    end

    private

    def action
      raise MISSING_METHOD_ERROR, "Please define an `action` method in #{self.class.name}"
    end

    attr_accessor :rule

    def authorized?
      raise MISSING_METHOD_ERROR, "Please define an `authorized?` method in #{self.class.name}"
    end

    def skip_authorization
      @skip_authorization ||= params&.delete(:skip_authorization)
    end

    def success
      ServiceResponse.success(payload: { rule: rule })
    end

    def error
      ServiceResponse.error(message: rule.errors.messages, payload: { rule: rule })
    end

    def merge_request_activity_counter
      Gitlab::UsageDataCounters::MergeRequestActivityUniqueCounter
    end

    def access_denied
      ServiceResponse.error(message: %w[Prohibited], reason: :access_denied)
    end
  end
end
