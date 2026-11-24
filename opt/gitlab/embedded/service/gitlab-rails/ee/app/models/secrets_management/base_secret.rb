# frozen_string_literal: true

module SecretsManagement
  class BaseSecret
    include ActiveModel::Model
    include ActiveModel::Attributes
    include ActiveModel::Validations
    include ActiveModel::Dirty
    include SecretStatus

    attribute :name, :string
    attribute :description, :string
    attribute :environment, :string
    attribute :rotation_info
    attribute :metadata_version, :integer, default: 0
    attribute :create_started_at
    attribute :create_completed_at
    attribute :update_started_at
    attribute :update_completed_at

    define_attribute_methods :environment

    SECRET_NAME_FORMAT = /\A[a-zA-Z0-9_]+\z/
    SECRET_NAME_FORMAT_MESSAGE = "can contain only letters, digits and '_'."

    # OpenBao rejects KV custom metadata values that are empty, longer than 512 bytes
    # or contain unprintable characters. A rejected metadata write leaves the
    # already-written value behind without metadata.
    MAX_CUSTOM_METADATA_VALUE_BYTES = 512
    # Mirrors Go's unicode.IsPrint: letters, marks, numbers, punctuation, symbols and ASCII space.
    CUSTOM_METADATA_VALUE_FORMAT = /\A[\p{L}\p{M}\p{N}\p{P}\p{S} ]*\z/
    CUSTOM_METADATA_VALUE_FORMAT_MESSAGE = 'contains unprintable characters.'

    validates :name,
      presence: true,
      length: { maximum: 255 },
      format: { with: SECRET_NAME_FORMAT, message: SECRET_NAME_FORMAT_MESSAGE }

    validates :environment, presence: true

    validates :description, length: { minimum: 1 }, allow_nil: true
    validates :description, :environment,
      bytesize: { maximum: -> { MAX_CUSTOM_METADATA_VALUE_BYTES } },
      format: { with: CUSTOM_METADATA_VALUE_FORMAT, message: CUSTOM_METADATA_VALUE_FORMAT_MESSAGE },
      allow_nil: true

    def initialize(attributes = {})
      super

      # Mark current state as the baseline for dirty tracking
      changes_applied
    end

    def ==(other)
      other.is_a?(self.class) && attributes == other.attributes
    end

    # Add methods to track attribute changes
    def environment=(val)
      environment_will_change! unless val == environment
      super
    end
  end
end
