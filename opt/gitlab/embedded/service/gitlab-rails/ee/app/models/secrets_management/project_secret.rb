# frozen_string_literal: true

module SecretsManagement
  class ProjectSecret < BaseSecret
    attribute :project

    attribute :branch, :string

    define_attribute_methods :branch

    validates :project, presence: true

    validates :branch,
      presence: true,
      bytesize: { maximum: -> { MAX_CUSTOM_METADATA_VALUE_BYTES } },
      format: { with: CUSTOM_METADATA_VALUE_FORMAT, message: CUSTOM_METADATA_VALUE_FORMAT_MESSAGE }

    # Add methods to track attribute changes
    def branch=(val)
      branch_will_change! unless val == branch
      super
    end
  end
end
