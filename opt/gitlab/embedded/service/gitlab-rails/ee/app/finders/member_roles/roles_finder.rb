# frozen_string_literal: true

# Search for member roles
module MemberRoles
  class RolesFinder
    include ::GitlabSubscriptions::SubscriptionHelper

    attr_reader :current_user, :params, :parent

    VALID_PARAMS = [:parent, :id].freeze

    ALLOWED_SORT_VALUES = %i[id created_at name].freeze
    DEFAULT_SORT_VALUE = :name

    ALLOWED_SORT_DIRECTIONS = %i[asc desc].freeze
    DEFAULT_SORT_DIRECTION = :asc

    def initialize(current_user, params = {})
      @current_user = current_user
      @parent = params.delete(:parent)
      @params = params
    end

    def execute
      return MemberRole.none unless current_user && License.feature_available?(:custom_roles)

      validate_arguments!

      items = member_roles
      items = by_parent(items)
      items = by_id(items)
      items = by_type(items)
      items = by_assignable(items)

      sort(items)
    end

    private

    def member_roles
      MemberRole.non_admin
    end

    def validate_arguments!
      return unless gitlab_com_subscription?
      return if parent.present?
      return if params[:id].present?

      raise ArgumentError, 'at least one filter param, :parent or :id has to be provided'
    end

    def by_assignable(items)
      return items unless params[:assignable] && parent.present?

      items.id_in(assignable_ids(items))
    end

    def by_parent(items)
      return items unless gitlab_com_subscription?
      return items if parent.blank?

      return MemberRole.none unless allowed_read_member_role?(parent)

      parent.root_ancestor.member_roles
    end

    def by_id(items)
      return items if params[:id].blank?

      items = items.id_in(params[:id])

      items.by_namespace(allowed_namespace_ids(items))
    end

    def sort(items)
      order_by = ALLOWED_SORT_VALUES.include?(params[:order_by]) ? params[:order_by] : DEFAULT_SORT_VALUE
      order_direction = ALLOWED_SORT_DIRECTIONS.include?(params[:sort]) ? params[:sort] : DEFAULT_SORT_DIRECTION
      order_by = :id if order_by == :created_at

      items.order(order_by => order_direction) # rubocop:disable CodeReuse/ActiveRecord -- simple ordering
    end

    def by_type(items)
      return items if gitlab_com_subscription?

      return MemberRole.none unless allowed_read_member_role?

      items.for_instance
    end

    # This is used by the AllRolesFinder and AdminRolesFinder subclasses.
    def can_return_admin_roles?
      Ability.allowed?(current_user, :read_admin_role)
    end

    def allowed_namespace_ids(items)
      items.select { |item| allowed_read_member_role?(item.namespace, item) }.map(&:namespace_id)
    end

    def assignable_ids(items)
      items.filter_map do |item|
        item.id unless parent.custom_role_abilities_too_high?(
          current_user: current_user,
          target_member_role_id: item.id
        )
      end
    end

    def allowed_read_member_role?(group = nil, member_role = nil)
      return Ability.allowed?(current_user, :read_member_role, group) if group

      return Ability.allowed?(current_user, :read_member_role, member_role) if member_role

      Ability.allowed?(current_user, :read_member_role)
    end
  end
end
