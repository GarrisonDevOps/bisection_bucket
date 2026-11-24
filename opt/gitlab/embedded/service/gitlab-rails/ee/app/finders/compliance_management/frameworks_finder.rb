# frozen_string_literal: true

# FrameworksFinder
#
# Used to filter compliance frameworks by set of params
#
# Arguments:
#   current_user - which user use
#   params:
#     ids: [integer]
module ComplianceManagement
  class FrameworksFinder
    attr_accessor :current_user, :params

    def initialize(current_user, params = {})
      @current_user = current_user
      @params = params
    end

    def execute
      raise ArgumentError, 'filter param, :ids has to be provided' if ids.blank?

      items = ComplianceManagement::Framework.id_in(ids)

      items.with_namespaces(allowed_namespace_ids(items))
    end

    private

    def ids
      params[:ids]
    end

    def allowed_namespace_ids(items)
      return [] if items.empty?

      items.select { |item| authorized?(item) }.map(&:namespace_id).uniq
    end

    def authorized?(framework)
      Ability.allowed?(current_user, :read_compliance_framework, framework)
    end
  end
end
