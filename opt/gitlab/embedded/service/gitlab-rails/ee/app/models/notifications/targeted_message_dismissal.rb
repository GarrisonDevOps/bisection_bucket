# frozen_string_literal: true

module Notifications
  class TargetedMessageDismissal < ApplicationRecord
    belongs_to :targeted_message, optional: false
    belongs_to :user, optional: false
    belongs_to :namespace, optional: false

    validates :user_id, uniqueness: { scope: [:targeted_message_id, :namespace_id] }
  end
end
