# frozen_string_literal: true

module AuditEvents
  class RunnerAuditEventService
    include SafeFormatHelper
    include SafeRunnerToken

    attr_reader :runner

    # Logs an audit event related to a runner event
    #
    # @param [Ci::Runner] runner
    # @param [String, User] author the entity initiating the operation
    #   (e.g. a user, a runner registration, or a authentication token)
    # @param [Group, Project, nil] scope the scope that the operation applies to (nil represents the instance)
    # @param [String] name the audit event name
    # @param [String] message the format for the audit event message. Can include placeholders such as %{runner_type}
    # @param [Hash] additional_details extra details to store with the audit event
    # @param [Hash] kwargs additional placeholders for message
    def initialize(
      runner, author, scope, name:, message:, token_field: :runner_authentication_token, additional_details: {},
      **kwargs)
      @scope = runner.instance_type? ? Gitlab::Audit::InstanceScope.new : scope

      raise ArgumentError, 'Missing scope' if @scope.nil?
      raise ArgumentError, 'Missing message' if message.blank?

      @additional_details = additional_details.dup
      @additional_details[token_field] = safe_author(author) if author.is_a?(String)
      @additional_details[:errors] = runner.errors.full_messages if runner.errors.present?

      @runner = runner
      @name = name
      @message = message
      @kwargs = kwargs
      @author = if author.is_a?(User)
                  author
                else
                  ::Gitlab::Audit::CiRunnerTokenAuthor.new(
                    entity_type: @scope.class.name,
                    entity_path: @scope.full_path,
                    **@additional_details.slice(token_field))
                end
    end

    def track_event
      audit_context = {
        name: @name,
        author: @author,
        scope: @scope,
        target: @runner,
        target_details: runner_path,
        additional_details: @additional_details.presence,
        message: safe_format(@message, runner_type: runner_type, **@kwargs)
      }.compact

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    private

    def runner_type
      @runner.runner_type.chomp('_type')
    end

    def runner_path
      url_helpers = ::Gitlab::Routing.url_helpers

      if @runner.group_type?
        url_helpers.group_runner_path(@scope, @runner)
      elsif @runner.project_type?
        url_helpers.project_runner_path(@scope, @runner)
      else
        url_helpers.admin_runner_path(@runner)
      end
    end
  end
end
