# frozen_string_literal: true

module Gitlab
  module Scim
    class BaseProvisioningService
      include ::Gitlab::Utils::StrongMemoize

      PASSWORD_AUTOMATICALLY_SET = true
      SKIP_EMAIL_CONFIRMATION = false

      def initialize(parsed_hash, group = nil)
        raise ArgumentError, 'Group cannot be nil' if group.nil? && ::Gitlab.com?

        @group = group
        @parsed_hash = parsed_hash.dup
      end

      private

      def error_response(errors: nil, objects: [], status: nil)
        errors ||= objects.compact.flat_map { |obj| obj.errors.full_messages }
        status ||= errors.any? { |e| e.include?('has already been taken') } ? :conflict : :error

        ::Gitlab::Scim::ProvisioningResponse.new(status: status, message: errors.to_sentence)
      end

      def logger
        ::API::API.logger
      end

      def random_password
        ::User.random_password
      end

      def valid_username
        ::Gitlab::Auth::ExternalUsernameSanitizer.new(@parsed_hash[:username]).sanitize
      end

      def username_too_long?
        @parsed_hash[:username].to_s.length > ::User::MAX_USERNAME_LENGTH
      end

      def username_too_long_error_message
        format(_('Username cannot be longer than %{max_length} characters.'),
          max_length: ::User::MAX_USERNAME_LENGTH)
      end

      def missing_params
        @missing_params ||= ([:extern_uid, :email, :username] - @parsed_hash.keys)
      end

      def user_params
        @parsed_hash.tap do |hash|
          hash[:username] = valid_username
          hash[:password] = hash[:password_confirmation] = random_password
          hash[:password_automatically_set] = PASSWORD_AUTOMATICALLY_SET
        end
      end
    end
  end
end
