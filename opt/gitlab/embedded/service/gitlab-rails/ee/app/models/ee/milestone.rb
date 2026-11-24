# frozen_string_literal: true

module EE
  module Milestone
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include Elastic::ApplicationVersionedSearch
      include Elastic::UpdateAssociatedEpicsOnDateChange

      has_many :boards

      elastic_index_dependant_association :issues, on_change: :title
      elastic_index_dependant_association :issues, on_change: [:due_date, :start_date]
      elastic_index_dependant_association :issues, on_change: :state
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      override :with_web_entity_associations
      def with_web_entity_associations
        super.preload(project: [:invited_groups, { group: [:saml_provider] }])
      end
    end

    override :use_elasticsearch?
    def use_elasticsearch?
      return project.use_elasticsearch? if project

      group&.use_elasticsearch?
    end

    def supports_milestone_charts?
      resource_parent&.feature_available?(:milestone_charts) && weight_available?
    end

    alias_method :supports_timebox_charts?, :supports_milestone_charts?
  end
end
