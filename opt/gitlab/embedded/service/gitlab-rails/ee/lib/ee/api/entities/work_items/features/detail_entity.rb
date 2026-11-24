# frozen_string_literal: true

module EE
  module API
    module Entities
      module WorkItems
        module Features
          module DetailEntity
            extend ActiveSupport::Concern

            prepended do
              expose_feature :color,
                using: ::API::Entities::WorkItems::Features::Color,
                documentation: {
                  type: 'Entities::WorkItems::Features::Color',
                  desc: 'Display color of the work item. Premium and Ultimate only.'
                },
                expose_nil: true

              expose_feature :progress,
                using: ::API::Entities::WorkItems::Features::Progress,
                documentation: {
                  type: 'Entities::WorkItems::Features::Progress',
                  desc: 'Progress of the work item toward a target value. Ultimate only.'
                },
                expose_nil: true

              expose_feature :iteration,
                using: ::API::Entities::WorkItems::Features::Iteration,
                documentation: {
                  type: 'Entities::WorkItems::Features::Iteration',
                  desc: 'Iteration the work item is assigned to. Premium and Ultimate only.'
                },
                expose_nil: true

              expose_feature :health_status,
                using: ::API::Entities::WorkItems::Features::HealthStatusDetail,
                documentation: {
                  type: 'Entities::WorkItems::Features::HealthStatusDetail',
                  desc: 'Health status of the work item, with counts of its open descendants by health status. ' \
                    'Ultimate only.'
                },
                expose_nil: true

              expose_feature :weight,
                using: ::API::Entities::WorkItems::Features::Weight,
                documentation: {
                  type: 'Entities::WorkItems::Features::Weight',
                  desc: 'Weight of the work item and the weight rolled up from its child work items. ' \
                    'Premium and Ultimate only.'
                },
                expose_nil: true

              expose_feature :requirement_legacy,
                using: ::API::Entities::WorkItems::Features::RequirementLegacy,
                documentation: {
                  type: 'Entities::WorkItems::Features::RequirementLegacy',
                  desc: 'Legacy requirement linked to the requirement work item. Ultimate only.'
                },
                expose_nil: true

              expose_feature :status,
                using: ::API::Entities::WorkItems::Features::Status,
                documentation: {
                  type: 'Entities::WorkItems::Features::Status',
                  desc: 'Status of the work item. Premium and Ultimate only.'
                },
                expose_nil: true

              expose_feature :verification_status,
                using: ::API::Entities::WorkItems::Features::VerificationStatus,
                documentation: {
                  type: 'Entities::WorkItems::Features::VerificationStatus',
                  desc: 'Verification status of the requirement, from its latest test report. Ultimate only.'
                },
                expose_nil: true

              expose_feature :linked_items,
                using: ::API::Entities::WorkItems::Features::LinkedItems,
                documentation: {
                  type: 'Entities::WorkItems::Features::LinkedItems',
                  desc: 'Counts of blocking links. Blocking links are available in Premium and Ultimate only. ' \
                    'To list the linked items, use the `linked_items` endpoint.'
                },
                expose_nil: true

              expose_feature :agent_plan,
                using: ::API::Entities::WorkItems::Features::AgentPlanDetail,
                documentation: { type: 'Entities::WorkItems::Features::AgentPlanDetail' },
                expose_nil: true

              expose_feature :custom_fields,
                using: ::API::Entities::WorkItems::Features::CustomFields,
                documentation: {
                  type: 'Entities::WorkItems::Features::CustomFields',
                  desc: 'Custom fields available for the work item type and their values on this work item. ' \
                    'Premium and Ultimate only.'
                },
                expose_nil: true
            end
          end
        end
      end
    end
  end
end
