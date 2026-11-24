# frozen_string_literal: true

module EE
  module Gitlab
    module QuickActions
      module MergeRequestActions
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::QuickActions::Dsl
        include ::Gitlab::Utils::StrongMemoize

        included do
          attr_accessor :requested_duo_code_review_depth
          private :requested_duo_code_review_depth, :requested_duo_code_review_depth=

          desc { _('Change reviewers') }
          explanation { _('Change reviewers.') }
          execution_message { _('Changed reviewers.') }
          params '@user1 @user2'
          types MergeRequest
          condition do
            quick_action_target.allows_multiple_reviewers? &&
              quick_action_target.persisted? &&
              Ability.allowed?(current_user, :"admin_#{quick_action_target.to_ability_name}", project)
          end
          command :reassign_reviewer do |reassign_param|
            @updates[:reviewer_ids] = extract_users(reassign_param).map(&:id)
          end
        end

        DUO_CODE_REVIEW_DEPTH_OPTIONS = {
          '-lite' => ::Gitlab::Duo::CodeReview::LITE_DEPTH,
          '-standard' => ::Gitlab::Duo::CodeReview::STANDARD_DEPTH
        }.freeze

        # Takes `-lite` and `-standard` out of the reviewer list. Anything else, typos included,
        # stays in so the user lookup fails instead of silently running the default depth.
        # Where Standard reviews aren't available, Lite runs anyway, so only `-standard` stays in.
        override :extract_reviewer_users
        def extract_reviewer_users(reviewer_param)
          self.requested_duo_code_review_depth = nil
          words = reviewer_param.to_s.split(/[\s,]+/)
          return super if words.none? { |word| DUO_CODE_REVIEW_DEPTH_OPTIONS.key?(word) }

          standard_available = ::Gitlab::Duo::CodeReview.standard_available?(project: project)
          depth_options, user_words = words.partition do |word|
            DUO_CODE_REVIEW_DEPTH_OPTIONS.key?(word) && (standard_available || word == '-lite')
          end
          self.requested_duo_code_review_depth = DUO_CODE_REVIEW_DEPTH_OPTIONS[depth_options.last] if standard_available

          super(user_words.join(' '))
        end

        override :request_review_params
        def request_review_params
          return super unless requested_duo_code_review_depth

          { duo_code_review_depth: requested_duo_code_review_depth }
        end

        override :request_review_explanation
        def request_review_explanation(users)
          duo_users, other_users = users.partition(&:duo_code_review_bot?)
          return super unless requested_duo_code_review_depth && duo_users.any?

          reviewers = { reviewer_users_sentence: reviewer_users_sentence(duo_users) }

          duo_message =
            if requested_duo_code_review_depth == ::Gitlab::Duo::CodeReview::STANDARD_DEPTH
              format(_('Requests a Standard review from %{reviewer_users_sentence}.'), reviewers)
            else
              format(_('Requests a Lite review from %{reviewer_users_sentence}.'), reviewers)
            end

          [(super(other_users) if other_users.any?), duo_message].compact.join(' ')
        end

        override :request_review_execution_message
        def request_review_execution_message(users)
          duo_users, other_users = users.partition(&:duo_code_review_bot?)
          return super unless requested_duo_code_review_depth && duo_users.any?

          reviewers = { reviewer_users_sentence: reviewer_users_sentence(duo_users) }

          duo_message =
            if requested_duo_code_review_depth == ::Gitlab::Duo::CodeReview::STANDARD_DEPTH
              format(_('Requested a Standard review from %{reviewer_users_sentence}.'), reviewers)
            else
              format(_('Requested a Lite review from %{reviewer_users_sentence}.'), reviewers)
            end

          [(super(other_users) if other_users.any?), duo_message].compact.join(' ')
        end

        override :process_reviewer_users
        def process_reviewer_users(users)
          strong_memoize_with(:process_reviewer_users, users.map(&:id)) do
            next users if users.empty?
            next users if users.none?(&:duo_code_review_bot?)
            next users if quick_action_target.ai_review_merge_request_allowed?(current_user)

            # Set flag to use in execution_message and flash message in controller
            quick_action_target.duo_code_review_attempted = :manual

            users.reject(&:duo_code_review_bot?)
          end
        end

        override :process_reviewer_users_message
        def process_reviewer_users_message
          return unless quick_action_target.duo_code_review_attempted

          ::Gitlab::Duo::CodeReview::Messages.manual_error
        end

        override :auto_merge_strategy_copy
        def auto_merge_strategy_copy(strategy, type)
          case strategy
          when ::EE::AutoMergeService::STRATEGY_MERGE_TRAIN
            case type
            when :desc then _('Add to merge train')
            when :explanation then _('Adds this merge request to merge train.')
            when :feedback then _('Added to merge train.')
            end
          when ::AutoMergeService::STRATEGY_ADD_TO_MERGE_TRAIN_WHEN_CHECKS_PASS
            case type
            when :desc then _('Add to merge train when ready')
            when :explanation then _('Adds this merge request to merge train when ready.')
            when :feedback then _('Set to add to merge train when ready.')
            end
          else
            super
          end
        end
      end
    end
  end
end
