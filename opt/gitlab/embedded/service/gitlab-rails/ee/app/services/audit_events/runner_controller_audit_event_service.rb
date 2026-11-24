# frozen_string_literal: true

module AuditEvents
  class RunnerControllerAuditEventService
    def initialize(target, author, name:, message:, additional_details: {})
      raise ArgumentError, 'Missing target' if target.nil?
      raise ArgumentError, 'Missing author' if author.nil?
      raise ArgumentError, 'Missing message' if message.blank?

      @target = target
      @author = author
      @name = name
      @message = message
      @additional_details = additional_details
    end

    def track_event
      audit_context = {
        name: @name,
        author: @author,
        scope: ::Gitlab::Audit::InstanceScope.new,
        target: @target,
        target_details: target_details,
        additional_details: @additional_details.presence,
        message: @message
      }.compact

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    private

    def target_details
      case @target
      when ::Ci::RunnerController
        "Runner controller ##{@target.id}"
      when ::Ci::RunnerControllerToken
        "Runner controller token ##{@target.id}"
      when ::Ci::RunnerControllerInstanceLevelScoping
        "Instance scope for runner controller ##{@target.runner_controller_id}"
      when ::Ci::RunnerControllerRunnerLevelScoping
        "Runner scope for runner ##{@target.runner_id} on runner controller ##{@target.runner_controller_id}"
      else
        @target.to_s
      end
    end
  end
end
