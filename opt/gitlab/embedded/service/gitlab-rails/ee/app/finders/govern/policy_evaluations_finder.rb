# frozen_string_literal: true

module Govern
  # Lists the policy evaluations of a container, newest first, for the
  # Policy Store UI. Callers are responsible for authorization.
  #
  # An organization lists every evaluation it holds; a group lists the evaluations
  # of its own and descendant policies, plus inherited ones run in its projects.
  # Any other container yields none.
  #
  # Filter params: policy_id, mode, verdict, evaluated_after, evaluated_before.
  class PolicyEvaluationsFinder
    def initialize(container:, params: {})
      @container = container
      @params = params
    end

    def execute
      evaluations = base_relation
      evaluations = by_policy(evaluations)
      evaluations = by_mode(evaluations)
      evaluations = by_verdict(evaluations)
      evaluations = by_evaluated_at(evaluations)

      evaluations.order_by_evaluated_at_desc
    end

    private

    attr_reader :container, :params

    def base_relation
      case container
      when ::Organizations::Organization then PolicyEvaluation.for_organization(container)
      when ::Group then group_relation
      else PolicyEvaluation.none
      end
    end

    # An inherited policy also runs in other groups' projects, and an evaluation with
    # no project can't be attributed to a group, so only this group's projects count.
    # Ids are plucked because namespaces and projects live in another database.
    def group_relation
      organization_evaluations = PolicyEvaluation.for_organization(container.organization)

      own_and_descendant = organization_evaluations.for_namespace(container.self_and_descendants.pluck_primary_key)
      inherited = organization_evaluations
        .for_namespace([nil, *container.ancestor_ids])
        .for_projects(container.all_projects.pluck_primary_key)

      own_and_descendant.or(inherited)
    end

    def by_policy(evaluations)
      return evaluations unless params[:policy_id]

      evaluations.for_policy(params[:policy_id])
    end

    def by_mode(evaluations)
      return evaluations unless params[:mode]

      evaluations.with_mode(params[:mode])
    end

    def by_verdict(evaluations)
      return evaluations unless params[:verdict]

      evaluations.with_verdict(params[:verdict])
    end

    def by_evaluated_at(evaluations)
      evaluations = evaluations.evaluated_after(params[:evaluated_after]) if params[:evaluated_after]
      evaluations = evaluations.evaluated_before(params[:evaluated_before]) if params[:evaluated_before]

      evaluations
    end
  end
end
