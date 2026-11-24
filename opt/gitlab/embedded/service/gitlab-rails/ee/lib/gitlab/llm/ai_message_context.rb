# frozen_string_literal: true

module Gitlab
  module Llm
    class AiMessageContext
      include ActiveModel::AttributeAssignment

      ATTRIBUTES_LIST = [
        :resource,
        :user_agent
      ].freeze

      attr_accessor(*ATTRIBUTES_LIST)

      delegate :[], :[]=, to: :attributes

      def initialize(attributes = {})
        assign_attributes(attributes.with_indifferent_access.slice(*ATTRIBUTES_LIST))
      end

      def to_h
        ATTRIBUTES_LIST.index_with do |attr|
          public_send(attr) # rubocop:disable GitlabSecurity/PublicSend -- to avoid duplication with ATTRIBUTES_LIST.
        end.compact.with_indifferent_access
      end
    end
  end
end
