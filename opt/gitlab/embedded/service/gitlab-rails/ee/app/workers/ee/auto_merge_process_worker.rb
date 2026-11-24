# frozen_string_literal: true

module EE
  module AutoMergeProcessWorker # rubocop:disable Gitlab/BoundedContexts -- Existing module
    extend ::Gitlab::Utils::Override

    private

    override :all_merge_requests
    def all_merge_requests(params)
      project_merge_requests = params['project_id'].try do |proj_id|
        project = ::Project.id_in(proj_id).first

        break [] unless project
        break [] unless project.licensed_feature_available?(:merge_request_title_regex_check)

        project.merge_requests&.with_auto_merge_enabled&.take(::AutoMergeProcessWorker::PROJECT_MR_LIMIT)
      end

      (super + project_merge_requests.to_a).uniq
    end
  end
end
