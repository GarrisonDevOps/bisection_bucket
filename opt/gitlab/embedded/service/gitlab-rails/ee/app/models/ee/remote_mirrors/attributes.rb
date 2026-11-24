# frozen_string_literal: true

module EE
  module RemoteMirrors
    module Attributes
      extend ::Gitlab::Utils::Override

      EE_ALLOWED_ATTRIBUTES = %i[mirror_branch_regex].freeze

      override :keys
      def keys
        super + EE_ALLOWED_ATTRIBUTES
      end

      override :allowed
      def allowed
        super.tap do |params|
          if params[:mirror_branch_regex].present?
            params[:only_protected_branches] = false
          elsif params[:only_protected_branches]
            params[:mirror_branch_regex] = nil
          end
        end
      end
    end
  end
end
