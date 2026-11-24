# frozen_string_literal: true

module Ai
  class FlowTriggerPolicy < ::BasePolicy
    delegate { @subject.container }

    condition(:group_trigger, scope: :subject) { @subject.group_id.present? }

    condition(:item_consumer_readable) { can?(:read_ai_catalog_item_consumer, @subject.ai_catalog_item_consumer) }

    rule { group_trigger & ~item_consumer_readable }.policy do
      prevent :read_ai_flow_triggers
      prevent :manage_ai_flow_triggers
    end
  end
end
