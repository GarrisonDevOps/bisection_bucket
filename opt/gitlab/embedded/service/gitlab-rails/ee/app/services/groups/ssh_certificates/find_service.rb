# frozen_string_literal: true

module Groups
  module SshCertificates
    class FindService
      Reason = ::Gitlab::SshCertificates::Reason

      def initialize(ca_fingerprint, user_identifier, namespace_id: nil)
        @ca_fingerprint = ca_fingerprint
        @user_identifier = user_identifier
        @namespace_id = namespace_id
      end

      def execute
        if namespace_id
          find_by_namespace
        else
          find_across_namespaces
        end
      end

      private

      attr_reader :ca_fingerprint, :user_identifier, :namespace_id

      def find_by_namespace
        certificate = ::Groups::SshCertificate.for_fingerprint(ca_fingerprint).for_namespace(namespace_id).first
        return error('Certificate Not Found', Reason::CERTIFICATE_NOT_FOUND) unless certificate

        validate_certificate(certificate)
      end

      def find_across_namespaces
        certificates = ::Groups::SshCertificate.for_fingerprint(ca_fingerprint)
        return error('Certificate Not Found', Reason::CERTIFICATE_NOT_FOUND) if certificates.empty?

        user = ::User.find_by_login(user_identifier)
        return error('User Not Found', Reason::USER_NOT_FOUND) unless user

        last_error = nil
        certificates.each do |certificate|
          result = validate_certificate(certificate, user: user)
          return result if result.success?

          last_error = result
        end

        last_error
      end

      def validate_certificate(certificate, user: nil)
        group = certificate.group
        unless group.licensed_feature_available?(:ssh_certificates)
          return error('Feature is not available', Reason::FEATURE_NOT_AVAILABLE)
        end

        user ||= ::User.find_by_login(user_identifier)
        user = group.all_group_members.non_invite.with_user(user).first ? user : nil

        return error('User Not Found', Reason::USER_NOT_FOUND) unless user

        unless user.enterprise_user_of_group?(group)
          return error('Not an Enterprise User of the group', Reason::NOT_ENTERPRISE_USER)
        end

        ServiceResponse.success(payload: { user: user, group: group })
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
