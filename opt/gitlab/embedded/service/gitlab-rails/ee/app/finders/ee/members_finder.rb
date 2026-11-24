# frozen_string_literal: true

module EE
  module MembersFinder # rubocop:disable Gitlab/BoundedContexts -- existing non-EE module is not bounded
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    private

    override :filter_by_max_role
    def filter_by_max_role(members)
      member_role_id = get_member_role_id(params[:max_role])
      return super unless member_role_id

      members.with_member_role_id(member_role_id)
    end
  end
end
