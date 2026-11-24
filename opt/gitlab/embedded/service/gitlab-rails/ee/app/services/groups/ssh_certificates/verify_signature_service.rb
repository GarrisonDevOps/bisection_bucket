# frozen_string_literal: true

# If a commit signature is a certificate, this class verifies whether this certificate
# has been issued by a CA configured in the top-level group
#
# This class does not check the validity of the signature, it's the responsibility of a caller
module Groups
  module SshCertificates
    class VerifySignatureService
      include ::Gitlab::Utils::StrongMemoize

      def initialize(project, committer_email, certificate)
        @project = project
        @committer_email = committer_email
        @certificate = certificate
      end

      # Returns verification status of the commit signature
      #
      # verify_ca - if the certificate is valid and can be tied to a top-level group
      # unverified - if the certificate is not verified and SSH certificates are enforced
      # nil - if none of the above happen, in order to check the certificate as if it's a regular SSH key
      def execute
        if verified?
          :verified_ca
        elsif root_namespace.enforce_ssh_certificates?
          :unverified
        end
      end

      private

      attr_reader :project, :certificate, :committer_email

      def verified?
        return false unless certificate_valid?

        group, user = associated_group_and_user

        # Verify that the certificate has been issued for the project's top-level
        return false unless group == root_namespace

        # Verify that the user has the committer emails in verified emails
        user.verified_emails.include?(committer_email)
      end
      strong_memoize_attr :verified?

      def root_namespace
        project.namespace.root_ancestor
      end
      strong_memoize_attr :root_namespace

      def associated_group_and_user
        response = ::Groups::SshCertificates::FindService.new(
          certificate.ca_key.fingerprint, certificate.key_id, namespace_id: root_namespace.id
        ).execute

        response.payload.values_at(:group, :user) if response.success?
      end

      def certificate_valid?
        return false unless certificate.is_a?(SSHData::Certificate)
        return false unless certificate.verify

        Time.current.between?(certificate.valid_after, certificate.valid_before)
      end
    end
  end
end
