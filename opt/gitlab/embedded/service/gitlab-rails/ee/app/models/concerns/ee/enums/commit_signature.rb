# frozen_string_literal: true

module EE
  module Enums
    module CommitSignature
      extend ActiveSupport::Concern

      EE_VERIFICATION_STATUSES = {
        verified_ca: 20
      }.freeze

      class_methods do
        extend ::Gitlab::Utils::Override

        override :verification_statuses
        def verification_statuses
          super.merge(EE_VERIFICATION_STATUSES)
        end
      end
    end
  end
end
