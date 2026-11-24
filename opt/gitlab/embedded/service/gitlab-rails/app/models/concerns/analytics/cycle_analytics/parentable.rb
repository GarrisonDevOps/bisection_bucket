# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    module Parentable
      extend ActiveSupport::Concern

      included do
        belongs_to :namespace, class_name: 'Namespace', foreign_key: :group_id, optional: false # rubocop: disable Rails/InverseOf -- this relation is not present on Namespace

        scope :for_organization, ->(organization) do
          joins(:namespace).where(namespaces: { organization_id: organization })
        end
      end
    end
  end
end
