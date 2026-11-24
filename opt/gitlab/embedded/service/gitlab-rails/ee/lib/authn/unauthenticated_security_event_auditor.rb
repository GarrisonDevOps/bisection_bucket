# frozen_string_literal: true

module Authn
  class UnauthenticatedSecurityEventAuditor
    attr_reader :author, :scope, :authentication_method

    def initialize(
      user_or_login, authentication_method = 'STANDARD',
      event_name: nil, message: nil, additional_details: {}, ip_address: nil)
      @authentication_method = authentication_method
      @event_name = event_name
      @message = message
      @additional_details = additional_details
      @ip_address = ip_address

      if user_or_login.is_a?(::User) && user_or_login.persisted?
        @author = @scope = user_or_login
      else
        login = user_or_login.is_a?(::User) ? user_or_login.username : user_or_login
        @author = ::Gitlab::Audit::UnauthenticatedAuthor.new(name: login)
        @scope = ::Gitlab::Audit::InstanceScope.new
      end
    end

    def execute
      context = {
        name: @event_name || "login_failed_with_#{@authentication_method.downcase}_authentication",
        scope: @scope,
        author: @author,
        target: @author,
        message: @message || "Failed to login with #{@authentication_method} authentication",
        additional_details: @additional_details.merge(failed_login: @authentication_method)
      }
      context[:ip_address] = @ip_address if @ip_address

      ::Gitlab::Audit::Auditor.audit(context)
    end
  end
end
