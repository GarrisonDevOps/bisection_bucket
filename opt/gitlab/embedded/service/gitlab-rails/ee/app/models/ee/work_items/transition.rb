# frozen_string_literal: true

module EE
  module WorkItems
    module Transition
      extend ActiveSupport::Concern

      prepended do
        belongs_to :promoted_to_epic, class_name: 'Epic', optional: true
      end

      def promoted?
        !!promoted_to_epic_id
      end
    end
  end
end
