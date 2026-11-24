# frozen_string_literal: true

module Integrations
  module Base
    module AmazonQ
      extend ActiveSupport::Concern

      AVAILABILITY_OPTIONS = %w[default_on default_off never_on].freeze

      included do
        validates :role_arn, presence: true, length: { maximum: 2048 }, if: :activated?
        validate :role_arn_changeable_on_instance_level
        validates :availability, inclusion: {
          in: AVAILABILITY_OPTIONS,
          message: "must be one of: #{AVAILABILITY_OPTIONS.join(', ')}"
        }, presence: true, if: :activated?
        validates :auto_review_enabled, inclusion: { in: [false], message: "integration must be available" },
          unless: ->(integration) { integration.availability == "default_on" }
        validates :merge_requests_events, :pipeline_events, inclusion: { in: ->(i) {
          [i.auto_review_enabled]
        }, message: "must be equal to auto_review_enabled" }

        field :role_arn, required: true, api_only: true
        field :availability, required: true, api_only: true
        field :auto_review_enabled, type: :checkbox, api_only: true

        attribute :merge_requests_events, default: false
        attribute :pipeline_events, default: false

        attribute :alert_events, default: false
        attribute :commit_events, default: false
        attribute :confidential_issues_events, default: false
        attribute :confidential_note_events, default: false
        attribute :issues_events, default: false
        attribute :job_events, default: false
        attribute :note_events, default: false
        attribute :push_events, default: false
        attribute :tag_push_events, default: false
        attribute :wiki_page_events, default: false

        def auto_review_enabled=(value)
          # Implementation from prop_accessor since we don't have a super method at this stage
          self.properties ||= {}
          updated_properties['auto_review_enabled'] = :auto_review_enabled unless auto_review_enabled_changed?
          self.properties = self.properties.merge('auto_review_enabled' => value)

          self.merge_requests_events = value
          self.pipeline_events = value
        end
      end

      class_methods do
        def title
          s_('AmazonQ|Amazon Q')
        end

        def description
          s_('AmazonQ|Use GitLab Duo with Amazon Q to create and review merge requests and upgrade Java.')
        end

        def help
          build_help_page_url(
            'user/duo_amazon_q/index.md',
            s_('AmazonQ|Use GitLab Duo with Amazon Q to create and review merge requests and upgrade Java. ' \
              'GitLab Duo with Amazon Q is separate from GitLab Duo Pro and Enterprise.')
          )
        end

        def to_param
          'amazon_q'
        end

        def supported_events
          %w[merge_request pipeline]
        end
      end

      def sections
        [{
          type: 'amazon_q',
          title: s_('AmazonQ|Configure GitLab Duo with Amazon Q'),
          description: help,
          plan: 'ultimate'
        }]
      end

      def editable?
        false
      end

      def manual_activation?
        false
      end

      def execute(data)
        return unless auto_review_enabled
        return unless duo_features_enabled_for_container?

        user = user_from_web_hook_data(data)
        return unless user

        client = ::Gitlab::Llm::QAi::Client.new(user)

        client.create_event(
          payload: { source: :web_hook, data: data },
          role_arn: ::Ai::Setting.for_organization_read_only(settings_organization).amazon_q_role_arn,
          event_id: WebHookService.hook_to_event("#{data[:object_kind]}_hooks")
        )
      end

      private

      # Rows can lag behind a Duo lock: propagation is async, instance-level propagation can copy the
      # instance flags back, and a project row with its own settings is never rewritten, so the
      # container's effective availability is the gate.
      def duo_features_enabled_for_container?
        container = project || group
        return true unless container

        container.duo_features_enabled
      end

      # Project- and group-level integrations derive the organization from
      # their container; instance-level integrations carry their own.
      def settings_organization
        project&.organization || group&.organization || organization
      end

      def role_arn_changeable_on_instance_level
        return if instance_level? || new_record? || !role_arn_changed?

        errors.add(:role_arn, "can be changed on only instance level")
      end

      def user_from_web_hook_data(data)
        user = ::User.find_by_id(data.dig(:user, :id))
        composite_identity = ::Gitlab::Auth::Identity.fabricate(user)

        return user unless composite_identity&.composite?

        # If a composite identity was propagated through Sidekiq and the user is service account
        # that requires composite identity, we can use the scoped user.
        return unless composite_identity.valid?

        composite_identity.scoped_user
      end
    end
  end
end
