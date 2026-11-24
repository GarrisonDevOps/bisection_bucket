# frozen_string_literal: true

module EE
  module Gitlab
    module Ssh
      module Signature
        include ::Gitlab::Utils::StrongMemoize
        extend ::Gitlab::Utils::Override

        private

        override :calculate_verification_status
        def calculate_verification_status
          ca_verification_status || super
        end

        def ca_verification_status
          ::Groups::SshCertificates::VerifySignatureService.new(
            commit.project, committer_email, signature.public_key
          ).execute
        end
        strong_memoize_attr :ca_verification_status
      end
    end
  end
end
