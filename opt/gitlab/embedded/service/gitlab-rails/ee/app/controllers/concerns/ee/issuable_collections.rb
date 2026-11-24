# frozen_string_literal: true

module EE
  module IssuableCollections
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    override :preload_for_collection
    def preload_for_collection
      @preload_for_collection ||= case collection_type
                                  when 'MergeRequest'
                                    super + [approval_rules: [:users, :group_users], approval_project_rules: [:users, :group_users]]
                                  when 'Issue'
                                    super + issue_preloads
                                  else
                                    super
                                  end
    end

    private

    def issue_preloads
      [].tap do |issue_params|
        issue_params << :epic_issue if include_subepics_param.present?
      end
    end

    def include_subepics_param
      params.permit(:include_subepics)[:include_subepics]
    end
  end
end
