# frozen_string_literal: true

module SecretsManagement
  class GroupSecret < BaseSecret
    attribute :group

    attribute :protected, :boolean, default: false

    define_attribute_methods :protected

    validates :group, presence: true

    validates :protected, inclusion: { in: [true, false] }

    # Add methods to track attribute changes
    def protected=(val)
      protected_will_change! unless val == protected
      super
    end
  end
end
