# frozen_string_literal: true

module Groups
  class SavedRepliesFinder < Base
    include FinderWithGroupHierarchy
    include Gitlab::Utils::StrongMemoize

    def initialize(group, params = {})
      @group = group
      @params = params
      @skip_authorization = true
    end

    def execute
      return group.saved_replies unless params[:include_ancestor_groups]

      ::Groups::SavedReply.for_groups(group_ids_for(group))
    end

    private

    attr_reader :group, :params, :skip_authorization
  end
end
