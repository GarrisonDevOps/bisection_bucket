# frozen_string_literal: true

module API
  module Entities
    module InternalPostReceive
      class Response < Grape::Entity
        expose :messages, using: Entities::InternalPostReceive::Message, documentation: { is_array: true }
        expose :reference_counter_decreased
      end
    end
  end
end
