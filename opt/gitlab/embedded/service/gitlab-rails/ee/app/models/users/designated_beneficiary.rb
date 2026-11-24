# frozen_string_literal: true

module Users
  class DesignatedBeneficiary < ApplicationRecord
    # Two types are very identical. The only difference is that successor has mandatory `relationship`.
    # It's easier to keep them as a single class until we need deeper customization.
    self.inheritance_column = nil # rubocop:disable Database/AvoidInheritanceColumn -- suppress single table inheritance

    belongs_to :user

    enum :type, {
      manager: 0,
      successor: 1
    }

    validates :name, presence: { message: N_("Full name is required") },
      length: { maximum: 255, too_long: N_("Full name is too long (maximum is 255 characters)") }
    validates :email, length: { maximum: 255, too_long: N_("Email is too long (maximum is 255 characters)") },
      format: { with: URI::MailTo::EMAIL_REGEXP }, allow_blank: true
    validates :relationship,
      length: { maximum: 255, too_long: N_("Relationship input is too long (maximum is 255 characters)") }

    validates :relationship, presence: { message: N_("Relationship is required") }, if: :successor?
    validates :type, presence: true
    validates :user_id, uniqueness: {
      scope: :type,
      message: ->(object, _data) do
        # rubocop:disable Layout/LineLength -- This is more readable
        format(_("Designated account %{type} already exists. You can edit or delete in the legacy contacts section below."), type: object.type)
        # rubocop:enable Layout/LineLength
      end
    }
  end
end
