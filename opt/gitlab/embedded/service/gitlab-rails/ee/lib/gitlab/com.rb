# frozen_string_literal: true

module Gitlab
  module Com
    ALLOWED_USER_IDS_KEY = 'gitlab_com_group_allowed_user_ids'
    FRIENDS_OF_THE_SLACK_APP_USER_IDS_KEY = 'friends_of_the_slack_app_allowed_user_ids'
    EXPIRY_TIME_L1_CACHE = 1.minute
    EXPIRY_TIME_L2_CACHE = 5.minutes
    GITLAB_COM_GROUP = 'gitlab-com'
    FRIENDS_OF_THE_SLACK_APP_PROJECT = 'gitlab-com/ai-engineering/friends-of-the-slack-app'

    def self.gitlab_com_group_member?(user_or_id)
      user_id = user_id_from(user_or_id)
      return false unless user_id

      Gitlab.com_except_jh? && gitlab_com_user_ids.include?(user_id) # rubocop:disable Gitlab/AvoidGitlabInstanceChecks
    end

    # Direct human members of the Friends of the Slack app project. Backs the
    # `friends_of_the_slack_app` feature group used for Duo in Slack early access.
    def self.friends_of_the_slack_app_member?(user_or_id)
      user_id = user_id_from(user_or_id)
      return false unless user_id

      # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- the roster project only exists on GitLab.com, same as gitlab_com_group_member?
      Gitlab.com_except_jh? && friends_of_the_slack_app_user_ids.include?(user_id)
      # rubocop:enable Gitlab/AvoidGitlabInstanceChecks
    end

    def self.user_id_from(user_or_id)
      case user_or_id
      when ::User then user_or_id.id
      when Integer then user_or_id
      end
    end
    private_class_method :user_id_from

    # rubocop: disable CodeReuse/ActiveRecord
    def self.gitlab_com_user_ids
      Gitlab::SafeRequestStore.fetch(:gitlab_com_user_ids) do
        l1_cache_backend.fetch(ALLOWED_USER_IDS_KEY, expires_in: EXPIRY_TIME_L1_CACHE) do
          l2_cache_backend.fetch(ALLOWED_USER_IDS_KEY, expires_in: EXPIRY_TIME_L2_CACHE) do
            group = Group.top_level.find_by(path: GITLAB_COM_GROUP)
            if group
              group.members.pluck_user_ids.to_set
            else
              []
            end
          end
        end
      end
    end
    private_class_method :gitlab_com_user_ids

    # Foundational-flow service accounts are added to the project as direct
    # members automatically, so only human members count.
    def self.friends_of_the_slack_app_user_ids
      Gitlab::SafeRequestStore.fetch(:friends_of_the_slack_app_user_ids) do
        l1_cache_backend.fetch(FRIENDS_OF_THE_SLACK_APP_USER_IDS_KEY, expires_in: EXPIRY_TIME_L1_CACHE) do
          l2_cache_backend.fetch(FRIENDS_OF_THE_SLACK_APP_USER_IDS_KEY, expires_in: EXPIRY_TIME_L2_CACHE) do
            project = Project.find_by_full_path(FRIENDS_OF_THE_SLACK_APP_PROJECT)
            if project
              project.members.joins(:user).merge(::User.human).pluck_user_ids.to_set
            else
              []
            end
          end
        end
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord
    private_class_method :friends_of_the_slack_app_user_ids

    def self.expire_allowed_user_ids_cache
      [ALLOWED_USER_IDS_KEY, FRIENDS_OF_THE_SLACK_APP_USER_IDS_KEY].each do |key|
        l1_cache_backend.delete(key)
        l2_cache_backend.delete(key)
      end
    end

    def self.l1_cache_backend
      Gitlab::ProcessMemoryCache.cache_backend
    end

    def self.l2_cache_backend
      Rails.cache
    end
  end
end
