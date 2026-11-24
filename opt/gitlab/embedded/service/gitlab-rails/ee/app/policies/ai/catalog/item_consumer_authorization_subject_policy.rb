# frozen_string_literal: true

module Ai
  module Catalog
    class ItemConsumerAuthorizationSubjectPolicy < ::BasePolicy
      delegate { @subject.item_consumer }

      condition(:inherited_by_project, scope: :subject) do
        @subject.inherited_by_project? &&
          ::Feature.enabled?(:ai_catalog_group_inherited_consumers, @subject.item_consumer.group)
      end

      condition(:project_member) { @subject.project.team.member?(@user) }
      condition(:project_grants_read) { can?(:read_ai_catalog_item_consumer, @subject.project) }
      condition(:project_grants_execute) { can?(:execute_ai_catalog_item, @subject.project) }

      rule { inherited_by_project & project_member & project_grants_read }.enable :read_ai_catalog_item_consumer
      rule { inherited_by_project & project_grants_execute }.enable :execute_ai_catalog_item
    end
  end
end
