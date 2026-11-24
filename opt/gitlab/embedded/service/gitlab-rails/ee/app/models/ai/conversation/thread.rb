# frozen_string_literal: true

module Ai
  module Conversation
    class Thread < ApplicationRecord
      EXPIRATION_COLUMNS = %w[last_updated_at created_at].freeze

      self.table_name = :ai_conversation_threads

      has_many :messages, class_name: 'Ai::Conversation::Message', inverse_of: :thread
      belongs_to :organization, class_name: 'Organizations::Organization'
      belongs_to :user

      validates :conversation_type, :user_id, presence: true

      scope :for_conversation_type, ->(conversation_type) { where(conversation_type: conversation_type) }
      scope :ordered, -> { order(last_updated_at: :desc) }

      enum :conversation_type, {
        duo_chat_legacy: 1,
        duo_code_review: 2,
        duo_quick_chat: 3,
        duo_chat: 4
      }

      before_create :populate_organization

      def self.expired(column, days)
        raise ArgumentError unless EXPIRATION_COLUMNS.include?(column.to_s)

        where(column => ...days.days.ago)
      end

      def to_new_thread!
        self.class.create!(
          attributes.slice(*%w[user_id organization_id conversation_type])
        )
      end

      private

      def populate_organization
        self.organization_id ||= user.organization.id
      end
    end
  end
end
