# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    module UserConcern
      extend ActiveSupport::Concern

      included do
        # Guests and minimal access users, while treated as non-billables in
        # namespaces under Ultimate plans, are also exempted from actions taken to
        # ensure PIPL compliance
        def belongs_to_paid_group?(user)
          user.authorized_groups.any? do |group|
            group.root_ancestor.paid?
          end
        end
      end
    end
  end
end
