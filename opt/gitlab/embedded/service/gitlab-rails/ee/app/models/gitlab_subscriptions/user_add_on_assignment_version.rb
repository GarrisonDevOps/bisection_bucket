# frozen_string_literal: true

module GitlabSubscriptions
  class UserAddOnAssignmentVersion < ApplicationRecord
    include PaperTrail::VersionConcern

    scope :for_add_on_purchases, ->(add_on_purchases) { where(purchase_id: add_on_purchases) }
  end
end
